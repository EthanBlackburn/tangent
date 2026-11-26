// daemon.swift: privileged capture daemon for `Tangent.app`.
//
//   tangent-sensor daemon [--socket-dir /var/run/tangent] [--uid <uid>]
//
// Runs as root under launchd (LaunchDaemon) so the user's `tangent` process
// never needs sudo after install and no LLM/WASM/network code runs as root.
//
// Exposes two Unix domain sockets in `socket-dir`, owned by `uid` (mode 0600),
// and checks `getpeereid` on every connection:
//   - `es.sock`  : NDJSON Endpoint Security stream (lazy-started on connect)
//   - `net.sock` : raw `/usr/sbin/tcpdump` lines (lazy-started on connect)
//
// While no client is connected, neither Endpoint Security nor tcpdump is
// running (0% CPU when paused).

import Darwin
import EndpointSecurity
import Foundation

private let defaultSocketDir = "/var/run/tangent"
private let tcpdumpPath = "/usr/sbin/tcpdump"

/// Exact same BPF filter as `crates/tangent/src/sources/macos/net.rs` so the
/// unprivileged client cannot supply arguments to root's tcpdump.
private let tcpdumpFilter = [
    "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)",
    "(ip6 and ip6[6] = 6 and ip6[53] & 0x12 = 0x02)",
    "(tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 and tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01)",
    "(ip6 and ip6[6] = 6 and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 0x16 and ip6[40 + ((ip6[52] & 0xf0) >> 2) + 5] = 0x01)",
    "(udp dst port 443 and udp[8] & 0xf0 = 0xc0)",
    "(ip6 and ip6[6] = 17 and ip6[42:2] = 443 and ip6[48] & 0xf0 = 0xc0)",
    "udp src port 53",
].joined(separator: " or ")

private let tcpdumpArgs = [
    "-i", "pktap,all", "-k", "NP", "-n", "-l", "-tt", "-X", tcpdumpFilter,
]

private struct DaemonArgs {
    let socketDir: String
    let uid: uid_t
    let gid: gid_t
}

private func parseDaemonArgs() -> DaemonArgs {
    var socketDir = defaultSocketDir
    var uidArg: uid_t? = nil
    let args = Array(CommandLine.arguments.dropFirst(2))
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--socket-dir":
            guard i + 1 < args.count else { fail("--socket-dir requires a path") }
            socketDir = args[i + 1]
            i += 2
        case "--uid":
            guard i + 1 < args.count, let parsed = UInt32(args[i + 1]) else {
                fail("--uid requires a numeric user id")
            }
            uidArg = uid_t(parsed)
            i += 2
        default:
            fail("unknown daemon argument: \(args[i])")
        }
    }
    let uid = uidArg ?? geteuid()
    var gid: gid_t = getegid()
    if let pw = getpwuid(uid) {
        gid = pw.pointee.pw_gid
    }
    return DaemonArgs(socketDir: socketDir, uid: uid, gid: gid)
}

/// Binds a Unix stream socket at `path`, owned by `uid:gid` with mode 0600.
private func bindUnixSocket(at path: String, uid: uid_t, gid: gid_t) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        fail("socket(\(path)) failed: \(String(cString: strerror(errno)))")
    }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(path.utf8)
    let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
    guard pathBytes.count < maxLen else {
        Darwin.close(fd)
        fail("socket path too long: \(path)")
    }
    withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
        ptr.withMemoryRebound(to: UInt8.self, capacity: maxLen) { dst in
            for (idx, byte) in pathBytes.enumerated() {
                dst[idx] = byte
            }
            dst[pathBytes.count] = 0
        }
    }
    // Remove any stale socket file without following symlinks.
    _ = Darwin.unlink(path)
    // Create the socket with restrictive umask so there is no window where it is world-accessible.
    let oldMask = umask(0o177)
    let bound = withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    umask(oldMask)
    guard bound == 0 else {
        let msg = String(cString: strerror(errno))
        Darwin.close(fd)
        fail("bind(\(path)) failed: \(msg)")
    }
    if geteuid() == 0 {
        if chown(path, uid, gid) != 0 {
            let msg = String(cString: strerror(errno))
            Darwin.close(fd)
            _ = Darwin.unlink(path)
            fail("chown(\(path)) failed: \(msg)")
        }
    }
    if chmod(path, 0o600) != 0 {
        let msg = String(cString: strerror(errno))
        Darwin.close(fd)
        _ = Darwin.unlink(path)
        fail("chmod(\(path)) failed: \(msg)")
    }
    guard Darwin.listen(fd, 4) == 0 else {
        let msg = String(cString: strerror(errno))
        Darwin.close(fd)
        _ = Darwin.unlink(path)
        fail("listen(\(path)) failed: \(msg)")
    }
    // Non-blocking listener so DispatchSource accept loops never stall.
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }
    return fd
}

/// Verifies the connected Unix peer belongs to `allowedUid` (or root).
private func peerAuthorized(_ clientFd: Int32, allowedUid: uid_t) -> Bool {
    var euid: uid_t = 0
    var egid: gid_t = 0
    guard getpeereid(clientFd, &euid, &egid) == 0 else {
        warn("getpeereid failed: \(String(cString: strerror(errno)))")
        return false
    }
    guard euid == allowedUid || euid == 0 else {
        warn("rejected connection from uid \(euid) (expected \(allowedUid))")
        return false
    }
    return true
}

/// Configures a connected client socket: SO_NOSIGPIPE and a bounded write
/// timeout so a stalled reader can never wedge Endpoint Security or shutdown.
private func configureClientSocket(_ fd: Int32) {
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    var tv = timeval(tv_sec: 2, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
}

/// Writes a single JSON control line to `fd`.
private func sendControl(_ object: [String: Any], to fd: Int32) -> Bool {
    guard var data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]) else {
        return false
    }
    data.append(0x0A)
    return writeAll(data, to: fd)
}

// MARK: Endpoint Security session (lazy on es.sock)

private final class ESSession {
    private let queue = DispatchQueue(label: "com.ethanblackburn.tangent.daemon.es")
    private let writeLock = NSLock()
    private var clientFd: Int32 = -1
    private var esClient: OpaquePointer?
    private var eofSource: DispatchSourceRead?

    func attach(fd: Int32) {
        queue.async { [weak self] in
            self?.attachLocked(fd: fd)
        }
    }

    func stopSync() {
        queue.sync {
            teardownLocked()
        }
    }

    private func attachLocked(fd: Int32) {
        teardownLocked()
        configureClientSocket(fd)

        let targetFd = fd
        switch openESClient(forApp: true, onLine: { [weak self] line in
            guard let self else { return }
            self.writeLock.lock()
            let current = self.clientFd
            let ok = (current == targetFd && current >= 0) ? writeAll(line, to: current) : false
            self.writeLock.unlock()
            if !ok {
                self.queue.async { [weak self] in
                    guard let self, self.clientFd == targetFd else { return }
                    self.teardownLocked()
                }
            }
        }) {
        case .failure(let err):
            _ = sendControl(["daemon_error": err.code, "message": err.message], to: fd)
            Darwin.close(fd)
        case .success(let client):
            writeLock.lock()
            clientFd = fd
            writeLock.unlock()
            esClient = client
            if !sendControl(["daemon_ready": true], to: fd) {
                teardownLocked()
                return
            }
            // Watch for client disconnect even when no ES events are firing.
            let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            src.setEventHandler { [weak self] in
                guard let self, self.clientFd == targetFd else { return }
                var byte: UInt8 = 0
                let n = Darwin.recv(targetFd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
                if n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    self.teardownLocked()
                }
            }
            eofSource = src
            src.resume()
        }
    }

    private func teardownLocked() {
        if let src = eofSource {
            eofSource = nil
            src.cancel()
        }
        // Invalidate clientFd before deleting the ES client so any in-flight
        // callback stops writing immediately, then delete the ES client
        // synchronously before closing the fd so it is never reused mid-write.
        writeLock.lock()
        let fd = clientFd
        clientFd = -1
        writeLock.unlock()

        if let client = esClient {
            esClient = nil
            es_unsubscribe_all(client)
            es_delete_client(client)
        }
        if fd >= 0 {
            Darwin.close(fd)
        }
    }
}

// MARK: tcpdump session (lazy on net.sock)

private final class NetSession {
    private let queue = DispatchQueue(label: "com.ethanblackburn.tangent.daemon.net")
    private let writeLock = NSLock()
    private var clientFd: Int32 = -1
    private var process: Process?
    private var eofSource: DispatchSourceRead?

    func attach(fd: Int32) {
        queue.async { [weak self] in
            self?.attachLocked(fd: fd)
        }
    }

    func stopSync() {
        queue.sync {
            teardownLocked()
        }
    }

    private func attachLocked(fd: Int32) {
        teardownLocked()
        configureClientSocket(fd)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: tcpdumpPath)
        proc.arguments = tcpdumpArgs
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            warn("starting \(tcpdumpPath) failed: \(error.localizedDescription)")
            Darwin.close(fd)
            return
        }

        writeLock.lock()
        clientFd = fd
        writeLock.unlock()
        process = proc

        let targetFd = fd
        let outHandle = outPipe.fileHandleForReading
        let errHandle = errPipe.fileHandleForReading

        // Drain tcpdump stderr so it never blocks its pipe.
        DispatchQueue.global(qos: .utility).async {
            while true {
                let data = errHandle.availableData
                if data.isEmpty { break }
            }
        }

        // Forward tcpdump stdout straight to the connected client socket.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            while true {
                let data = outHandle.availableData
                if data.isEmpty { break }
                guard let self else { break }
                self.writeLock.lock()
                let current = self.clientFd
                let ok = (current == targetFd && current >= 0) ? writeAll(data, to: current) : false
                self.writeLock.unlock()
                if !ok { break }
            }
            self?.queue.async { [weak self] in
                guard let self else { return }
                self.writeLock.lock()
                let stillSame = (self.clientFd == targetFd)
                self.writeLock.unlock()
                if stillSame {
                    self.teardownLocked()
                }
            }
        }

        // Watch for client disconnect even during quiet network periods.
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler { [weak self] in
            guard let self else { return }
            self.writeLock.lock()
            let stillSame = (self.clientFd == targetFd)
            self.writeLock.unlock()
            guard stillSame else { return }
            var byte: UInt8 = 0
            let n = Darwin.recv(targetFd, &byte, 1, MSG_PEEK | MSG_DONTWAIT)
            if n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                self.teardownLocked()
            }
        }
        eofSource = src
        src.resume()
    }

    private func teardownLocked() {
        if let src = eofSource {
            eofSource = nil
            src.cancel()
        }
        // Wake any blocked write before waiting on writeLock / process exit.
        let fdToClose: Int32
        writeLock.lock()
        fdToClose = clientFd
        if fdToClose >= 0 {
            _ = Darwin.shutdown(fdToClose, SHUT_RDWR)
            clientFd = -1
        }
        writeLock.unlock()

        if let proc = process {
            process = nil
            if proc.isRunning {
                proc.terminate()
            }
            proc.waitUntilExit()
        }
        if fdToClose >= 0 {
            Darwin.close(fdToClose)
        }
    }
}

// MARK: listener loop

private func acceptLoop(
    listenFd: Int32,
    allowedUid: uid_t,
    queue: DispatchQueue,
    onClient: @escaping (Int32) -> Void
) -> DispatchSourceRead {
    let source = DispatchSource.makeReadSource(fileDescriptor: listenFd, queue: queue)
    source.setEventHandler {
        while true {
            let clientFd = Darwin.accept(listenFd, nil, nil)
            if clientFd < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { break }
                warn("accept failed: \(String(cString: strerror(errno)))")
                break
            }
            guard peerAuthorized(clientFd, allowedUid: allowedUid) else {
                Darwin.close(clientFd)
                continue
            }
            onClient(clientFd)
        }
    }
    source.resume()
    return source
}

// Keep dispatch sources alive for the lifetime of the daemon.
private var activeSources: [DispatchSourceProtocol] = []

/// Entrypoint for `tangent-sensor daemon`.
func runDaemon() -> Never {
    signal(SIGPIPE, SIG_IGN)
    let args = parseDaemonArgs()

    do {
        try FileManager.default.createDirectory(
            atPath: args.socketDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
    } catch {
        fail("creating \(args.socketDir) failed: \(error.localizedDescription)")
    }

    let esPath = (args.socketDir as NSString).appendingPathComponent("es.sock")
    let netPath = (args.socketDir as NSString).appendingPathComponent("net.sock")

    let esListenFd = bindUnixSocket(at: esPath, uid: args.uid, gid: args.gid)
    let netListenFd = bindUnixSocket(at: netPath, uid: args.uid, gid: args.gid)

    let esSession = ESSession()
    let netSession = NetSession()

    let acceptQueue = DispatchQueue(label: "com.ethanblackburn.tangent.daemon.accept")
    activeSources.append(acceptLoop(listenFd: esListenFd, allowedUid: args.uid, queue: acceptQueue) { fd in
        esSession.attach(fd: fd)
    })
    activeSources.append(acceptLoop(listenFd: netListenFd, allowedUid: args.uid, queue: acceptQueue) { fd in
        netSession.attach(fd: fd)
    })

    let shutdown = {
        esSession.stopSync()
        netSession.stopSync()
        Darwin.close(esListenFd)
        Darwin.close(netListenFd)
        _ = Darwin.unlink(esPath)
        _ = Darwin.unlink(netPath)
        exit(0)
    }

    for sig in [SIGTERM, SIGINT] {
        signal(sig, SIG_IGN)
        let sigSource = DispatchSource.makeSignalSource(signal: sig, queue: acceptQueue)
        sigSource.setEventHandler(handler: shutdown)
        sigSource.resume()
        activeSources.append(sigSource)
    }

    dispatchMain()
}
