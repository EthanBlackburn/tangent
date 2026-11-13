// tangent-sensor: the macos pack's Endpoint Security client. It writes the
// events plugin macos reads, one JSON line each, to stdout:
//
//   sudo tangent-sensor | nc -U es.sock
//
// The lines are in the shape of eslogger's, Apple's own Endpoint Security
// tool, with its field names. A line holds what the plugin reads and leaves
// out the rest (the stat blocks, the code hashes), so it is about half the
// size of eslogger's. Nothing is filtered yet: every event of the ten kinds
// is written.
//
// It needs root, Full Disk Access for the terminal that starts it, and the
// com.apple.developer.endpoint-security.client entitlement, which Apple
// grants to a team and a provisioning profile carries (README.md).

import EndpointSecurity
import Foundation

// MARK: eslogger's values

func text(_ t: es_string_token_t) -> String {
    guard let data = t.data, t.length > 0 else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: data, count: t.length), as: UTF8.self)
}

/// eslogger's time: UTC, nine digits of a second.
func stamp(_ sec: Int, _ nsec: Int) -> String {
    var t = time_t(sec)
    var tm = tm()
    gmtime_r(&t, &tm)
    return String(
        format: "%04d-%02d-%02dT%02d:%02d:%02d.%09dZ",
        Int(tm.tm_year) + 1900, Int(tm.tm_mon) + 1, Int(tm.tm_mday),
        Int(tm.tm_hour), Int(tm.tm_min), Int(tm.tm_sec), nsec)
}

func token(_ a: audit_token_t) -> [String: Any] {
    [
        "asid": Int(audit_token_to_asid(a)),
        "auid": Int(audit_token_to_auid(a)),
        "egid": Int(audit_token_to_egid(a)),
        "euid": Int(audit_token_to_euid(a)),
        "pid": Int(audit_token_to_pid(a)),
        "pidversion": Int(audit_token_to_pidversion(a)),
        "rgid": Int(audit_token_to_rgid(a)),
        "ruid": Int(audit_token_to_ruid(a)),
    ]
}

/// A file: its path, without eslogger's `stat`.
func file(_ f: UnsafePointer<es_file_t>) -> [String: Any] {
    ["path": text(f.pointee.path), "path_truncated": f.pointee.path_truncated]
}

func file(_ f: UnsafeMutablePointer<es_file_t>?) -> Any {
    f.map { file(UnsafePointer($0)) } ?? NSNull()
}

func process(_ p: UnsafePointer<es_process_t>, _ version: UInt32) -> [String: Any] {
    let q = p.pointee
    var d: [String: Any] = [
        "audit_token": token(q.audit_token),
        "ppid": Int(q.ppid),
        "original_ppid": Int(q.original_ppid),
        "group_id": Int(q.group_id),
        "session_id": Int(q.session_id),
        "codesigning_flags": Int(q.codesigning_flags),
        "is_platform_binary": q.is_platform_binary,
        "is_es_client": q.is_es_client,
        "signing_id": text(q.signing_id),
        "team_id": q.team_id.length > 0 ? text(q.team_id) as Any : NSNull(),
        "executable": file(q.executable),
    ]
    if version >= 2 { d["tty"] = file(q.tty) }
    if version >= 3 {
        d["start_time"] = stamp(q.start_time.tv_sec, Int(q.start_time.tv_usec) * 1000)
    }
    if version >= 4 {
        d["responsible_audit_token"] = token(q.responsible_audit_token)
        d["parent_audit_token"] = token(q.parent_audit_token)
    }
    return d
}

func process(_ p: UnsafeMutablePointer<es_process_t>?, _ version: UInt32) -> Any {
    p.map { process(UnsafePointer($0), version) as Any } ?? NSNull()
}

/// Where a `create` or a `rename` wrote: a file that was there, or a new name
/// in a directory.
func destination(
    existing: Bool, file existingFile: UnsafeMutablePointer<es_file_t>?,
    dir: UnsafeMutablePointer<es_file_t>?, name: es_string_token_t
) -> [String: Any] {
    if existing {
        return ["existing_file": file(existingFile)]
    }
    return ["new_path": ["dir": file(dir), "filename": text(name)]]
}

// MARK: the ten events

let subscribed: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
]

/// The event under eslogger's name for it, and its body.
func event(_ m: UnsafePointer<es_message_t>) -> (String, [String: Any])? {
    let v = m.pointee.version
    switch m.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        // in place: the arguments and the environment are read through the
        // event's own address
        let offset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event)!
        let e = (UnsafeRawPointer(m) + offset).assumingMemoryBound(to: es_event_exec_t.self)
        var body: [String: Any] = [
            "target": process(UnsafePointer(e.pointee.target), v),
            "args": (0..<es_exec_arg_count(e)).map { text(es_exec_arg(e, $0)) },
            "env": (0..<es_exec_env_count(e)).map { text(es_exec_env(e, $0)) },
        ]
        if v >= 2 { body["script"] = file(e.pointee.script) }
        if v >= 3 { body["cwd"] = file(UnsafePointer(e.pointee.cwd)) }
        if v >= 7 { body["dyld_exec_path"] = text(e.pointee.dyld_exec_path) }
        return ("exec", body)
    case ES_EVENT_TYPE_NOTIFY_FORK:
        return ("fork", ["child": process(UnsafePointer(m.pointee.event.fork.child), v)])
    case ES_EVENT_TYPE_NOTIFY_EXIT:
        return ("exit", ["stat": Int(m.pointee.event.exit.stat)])
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        let e = m.pointee.event.open
        return ("open", ["fflag": Int(e.fflag), "file": file(UnsafePointer(e.file))])
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        let e = m.pointee.event.close
        var body: [String: Any] = ["modified": e.modified, "target": file(UnsafePointer(e.target))]
        if v >= 6 { body["was_mapped_writable"] = e.was_mapped_writable }
        return ("close", body)
    case ES_EVENT_TYPE_NOTIFY_CREATE:
        let e = m.pointee.event.create
        let existing = e.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
        return (
            "create",
            [
                "destination_type": Int(e.destination_type.rawValue),
                "destination": existing
                    ? destination(existing: true, file: e.destination.existing_file, dir: nil, name: es_string_token_t())
                    : destination(
                        existing: false, file: nil, dir: e.destination.new_path.dir,
                        name: e.destination.new_path.filename),
            ]
        )
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        let e = m.pointee.event.rename
        let existing = e.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
        return (
            "rename",
            [
                "source": file(UnsafePointer(e.source)),
                "destination_type": Int(e.destination_type.rawValue),
                "destination": existing
                    ? destination(existing: true, file: e.destination.existing_file, dir: nil, name: es_string_token_t())
                    : destination(
                        existing: false, file: nil, dir: e.destination.new_path.dir,
                        name: e.destination.new_path.filename),
            ]
        )
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        let e = m.pointee.event.unlink
        return (
            "unlink",
            ["target": file(UnsafePointer(e.target)), "parent_dir": file(UnsafePointer(e.parent_dir))]
        )
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
        let e = m.pointee.event.btm_launch_item_add.pointee
        let item = e.item.pointee
        return (
            "btm_launch_item_add",
            [
                "instigator": process(e.instigator, v),
                "app": process(e.app, v),
                "executable_path": text(e.executable_path),
                "item": [
                    "item_type": Int(item.item_type.rawValue),
                    "legacy": item.legacy,
                    "managed": item.managed,
                    "uid": Int(item.uid),
                    "item_url": text(item.item_url),
                    "app_url": text(item.app_url),
                ],
            ]
        )
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
        let e = m.pointee.event.tcc_modify.pointee
        return (
            "tcc_modify",
            [
                "service": text(e.service),
                "identity": text(e.identity),
                "identity_type": Int(e.identity_type.rawValue),
                "update_type": Int(e.update_type.rawValue),
                "instigator_token": token(e.instigator_token),
                "instigator": process(e.instigator, v),
                "responsible_token": e.responsible_token.map { token($0.pointee) as Any } ?? NSNull(),
                "responsible": process(e.responsible, v),
                "right": Int(e.right.rawValue),
                "reason": Int(e.reason.rawValue),
            ]
        )
    default:
        return nil
    }
}

// MARK: out

/// One line to stdout, whole. When the reader has gone the capture is over.
func write(line: Data) {
    line.withUnsafeBytes { buf in
        var done = 0
        while done < buf.count {
            let n = Darwin.write(STDOUT_FILENO, buf.baseAddress! + done, buf.count - done)
            if n < 0 {
                if errno == EINTR { continue }
                exit(errno == EPIPE ? 0 : 1)
            }
            done += n
        }
    }
}

func emit(_ m: UnsafePointer<es_message_t>) {
    guard let (kind, body) = event(m) else { return }
    let v = m.pointee.version
    var record: [String: Any] = [
        "time": stamp(m.pointee.time.tv_sec, m.pointee.time.tv_nsec),
        "mach_time": m.pointee.mach_time,
        "version": Int(v),
        "event_type": Int(m.pointee.event_type.rawValue),
        "process": process(UnsafePointer(m.pointee.process), v),
        "event": [kind: body],
    ]
    if v >= 2 { record["seq_num"] = m.pointee.seq_num }
    if v >= 4 { record["global_seq_num"] = m.pointee.global_seq_num }
    guard var line = try? JSONSerialization.data(withJSONObject: record, options: [.withoutEscapingSlashes])
    else { return }
    line.append(0x0A)
    write(line: line)
}

// MARK: main

func fail(_ why: String) -> Never {
    FileHandle.standardError.write(Data("tangent-sensor: \(why)\n".utf8))
    exit(1)
}

signal(SIGPIPE, SIG_IGN)  // a closed pipe is an error from write, handled there

var client: OpaquePointer?
let made = es_new_client(&client) { _, m in emit(m) }
switch made {
case ES_NEW_CLIENT_RESULT_SUCCESS: break
case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: fail("not root: run it with sudo")
case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    fail("not entitled: the binary is not signed with the Endpoint Security entitlement and a profile that grants it")
case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
    fail("not permitted: give the terminal Full Disk Access (System Settings, Privacy & Security) and restart it")
case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: fail("too many Endpoint Security clients are running")
default: fail("es_new_client failed (\(made.rawValue))")
}
guard let client else { fail("es_new_client gave no client") }
// one at a time: an older macOS does not know the newest of them (tcc_modify
// came with 15.4), and the rest are still worth having
var taken = 0
for kind in subscribed {
    if es_subscribe(client, [kind], 1) == ES_RETURN_SUCCESS {
        taken += 1
    } else {
        FileHandle.standardError.write(
            Data("tangent-sensor: this macOS does not report event type \(kind.rawValue): going on without it\n".utf8))
    }
}
guard taken > 0 else { fail("es_subscribe failed for every event") }
dispatchMain()
