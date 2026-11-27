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

/// Configures a connected client socket: blocking, SO_NOSIGPIPE, and room
/// for a burst.
///
/// macOS hands `accept` the listener's O_NONBLOCK, and with it a write to a
/// reader that is a few kilobytes behind fails at once with EAGAIN. So the
/// flag is cleared here, and a write waits for the reader as a write to the
/// pipe `sudo tangent-sensor` has does: tangent stops reading for seconds at
/// a time while a model is asked, and what the kernel cannot queue meanwhile
/// it drops and counts, which the sensor reports. A write is not given up on
/// after some time, which ended the capture every few minutes on a busy Mac.
/// What ends a write that waits is the session's teardown, which shuts the
/// socket down first.
///
/// A Unix socket queues 8 KB unless asked for more, where a pipe has 64: the
/// 4 MB asked for here is what rides out a burst without the reader.
private func configureClientSocket(_ fd: Int32) {
    let flags = fcntl(fd, F_GETFL, 0)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
    }
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    var room: Int32 = 4 << 20
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &room, socklen_t(MemoryLayout<Int32>.size))
}

/// Writes a single JSON control line to `fd`.
private func sendControl(_ object: [String: Any], to fd: Int32) -> Bool {
    guard var data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]) else {
        return false
    }
    data.append(0x0A)
    return writeAll(data, to: fd)
}

/// One thread that runs what it is given, in order. Endpoint Security wants
/// `es_delete_client` called from the thread that called `es_new_client`, and
/// a dispatch queue promises an order, not a thread.
private final class SerialThread {
    private let cond = NSCondition()
    private var jobs: [() -> Void] = []

    init(name: String) {
        let thread = Thread { [self] in
            while true {
                cond.lock()
                while jobs.isEmpty { cond.wait() }
                let job = jobs.removeFirst()
                cond.unlock()
                job()
            }
        }
        thread.name = name
        thread.start()
    }

    func async(_ job: @escaping () -> Void) {
        cond.lock()
        jobs.append(job)
        cond.signal()
        cond.unlock()
    }

    /// Runs `job` on the thread and waits for it. Not to be called from it.
    func sync(_ job: @escaping () -> Void) {
        let done = DispatchSemaphore(value: 0)
        async {
            job()
            done.signal()
        }
        done.wait()
    }
}

/// Watches a connected client for hanging up, which is the only thing a
/// client says: what it writes is read and dropped. It owns the socket from
/// here on, and closes it when cancelled, once its handler is out of it.
private final class HangupWatch {
    private let source: DispatchSourceRead
    private let lock = NSLock()
    private var suspended = false

    init(fd: Int32, queue: DispatchQueue, onHangup: @escaping () -> Void) {
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            var scratch = [UInt8](repeating: 0, count: 256)
            let n = Darwin.recv(fd, &scratch, scratch.count, MSG_DONTWAIT)
            if n > 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { return }
            // A socket at its end stays readable: no more of these until the
            // session is torn down.
            self.lock.lock()
            if !self.suspended {
                self.source.suspend()
                self.suspended = true
            }
            self.lock.unlock()
            onHangup()
        }
        source.setCancelHandler { Darwin.close(fd) }
        source.resume()
    }

    func cancel() {
        lock.lock()
        source.cancel()
        // A suspended source is not cancelled, and its socket not closed,
        // until it is resumed.
        if suspended {
            source.resume()
            suspended = false
        }
        lock.unlock()
    }
}

// MARK: Endpoint Security session (lazy on es.sock)

private final class ESSession {
    /// Everything here but the writes runs on this one thread.
    private let thread = SerialThread(name: "com.ethanblackburn.tangent.daemon.es")
    private let ioQueue = DispatchQueue(label: "com.ethanblackburn.tangent.daemon.es.io")
    private let writeLock = NSLock()
    /// The client being written to, once it has been told the daemon is
    /// ready. Set on the thread, under `writeLock`.
    private var clientFd: Int32 = -1
    private var esClient: OpaquePointer?
    private var hangup: HangupWatch?

    func attach(fd: Int32) {
        thread.async { [weak self] in
            self?.attachOnThread(fd: fd)
        }
    }

    func stopSync() {
        thread.sync { [weak self] in
            self?.teardownOnThread()
        }
    }

    private func teardownIfStill(_ fd: Int32) {
        thread.async { [weak self] in
            guard let self, self.clientFd == fd else { return }
            self.teardownOnThread()
        }
    }

    private func attachOnThread(fd: Int32) {
        teardownOnThread()
        configureClientSocket(fd)

        let targetFd = fd
        let opened = openESClient(forApp: true, onLine: { [weak self] line in
            guard let self else { return }
            self.writeLock.lock()
            // Events come as soon as each subscription is made, which is
            // before the client has been told the daemon is ready: those are
            // not this stream's yet, and are dropped. Only a write that was
            // tried and failed ends the session.
            let failed = self.clientFd == targetFd && !writeAll(line, to: targetFd)
            self.writeLock.unlock()
            if failed { self.teardownIfStill(targetFd) }
        })
        switch opened {
        case .failure(let err):
            _ = sendControl(["daemon_error": err.code, "message": err.message], to: fd)
            Darwin.close(fd)
        case .success(let client):
            esClient = client
            // The ready line and the first event's turn are decided under the
            // one lock, so no event is written ahead of it.
            writeLock.lock()
            let ready = sendControl(["daemon_ready": true], to: fd)
            if ready { clientFd = fd }
            writeLock.unlock()
            guard ready else {
                teardownOnThread()
                Darwin.close(fd)
                return
            }
            // Watch for client disconnect even when no ES events are firing.
            hangup = HangupWatch(fd: fd, queue: ioQueue) { [weak self] in
                self?.teardownIfStill(targetFd)
            }
        }
    }

    private func teardownOnThread() {
        // Only this thread sets clientFd, so it is read here without the
        // lock: a write that is waiting on a stalled reader holds the lock,
        // and this is what ends its wait.
        let fd = clientFd
        if fd >= 0 {
            _ = Darwin.shutdown(fd, SHUT_RDWR)
        }
        // Invalidate clientFd before deleting the ES client so any in-flight
        // callback stops writing, then delete the ES client before the socket
        // is closed so its number is never reused mid-write.
        writeLock.lock()
        clientFd = -1
        writeLock.unlock()

        if let client = esClient {
            esClient = nil
            es_unsubscribe_all(client)
            es_delete_client(client)
        }
        if let watch = hangup {
            hangup = nil
            watch.cancel()  // closes the socket
        } else if fd >= 0 {
            Darwin.close(fd)
        }
    }
}

// MARK: tcpdump session (lazy on net.sock)

private final class NetSession {
    private let queue = DispatchQueue(label: "com.ethanblackburn.tangent.daemon.net")
    private let writeLock = NSLock()
    /// Set on `queue`, under `writeLock`.
    private var clientFd: Int32 = -1
    private var process: Process?
    private var hangup: HangupWatch?

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

    private func teardownIfStill(_ fd: Int32) {
        queue.async { [weak self] in
            guard let self, self.clientFd == fd else { return }
            self.teardownLocked()
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

        // What tcpdump says goes to the daemon's log, a line at a time: it is
        // how a tcpdump that will not start says why. It says what it listens
        // on as it starts, too, which is no warning and is kept all the same.
        DispatchQueue.global(qos: .utility).async {
            var pending = Data()
            while true {
                let data = errHandle.availableData
                if data.isEmpty { break }
                pending.append(data)
                while let end = pending.firstIndex(of: 0x0A) {
                    let line = String(decoding: pending[pending.startIndex..<end], as: UTF8.self)
                    pending.removeSubrange(pending.startIndex...end)
                    if !line.isEmpty { warn("tcpdump: \(line)") }
                }
            }
            if !pending.isEmpty { warn("tcpdump: \(String(decoding: pending, as: UTF8.self))") }
        }

        // Forward tcpdump stdout straight to the connected client socket.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            while true {
                let data = outHandle.availableData
                if data.isEmpty { break }
                guard let self else { break }
                self.writeLock.lock()
                let ok = self.clientFd == targetFd && writeAll(data, to: targetFd)
                self.writeLock.unlock()
                if !ok { break }
            }
            self?.teardownIfStill(targetFd)
        }

        // Watch for client disconnect even during quiet network periods.
        hangup = HangupWatch(fd: fd, queue: queue) { [weak self] in
            guard let self, self.clientFd == targetFd else { return }
            self.teardownLocked()
        }
    }

    private func teardownLocked() {
        // Only `queue` sets clientFd, so it is read here without the lock: a
        // write that is waiting on a stalled reader holds the lock, and this
        // is what ends its wait.
        let fd = clientFd
        if fd >= 0 {
            _ = Darwin.shutdown(fd, SHUT_RDWR)
        }
        writeLock.lock()
        clientFd = -1
        writeLock.unlock()

        if let proc = process {
            process = nil
            if proc.isRunning {
                proc.terminate()
            }
            proc.waitUntilExit()
        }
        if let watch = hangup {
            hangup = nil
            watch.cancel()  // closes the socket
        } else if fd >= 0 {
            Darwin.close(fd)
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
