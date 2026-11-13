#!/usr/bin/env python3
"""compare.py DIR: eslogger.ndjson against sensor.ndjson (compare.sh writes
both), on the fields plugin macos reads: the events each saw in the time both
ran, matched by time, kind and pid. Prints counts and field names only, never
a value: the lines hold command lines and environments."""
import collections
import json
import os
import sys


def at(v, path):
    for k in path.split("/"):
        if not isinstance(v, dict):
            return None
        v = v.get(k)
    return v


def proc(p):
    if not isinstance(p, dict):
        return None
    return {
        "audit_token.pid": at(p, "audit_token/pid"),
        "audit_token.euid": at(p, "audit_token/euid"),
        "ppid": p.get("ppid"),
        "executable.path": at(p, "executable/path"),
        "signing_id": p.get("signing_id") or None,
        "team_id": p.get("team_id") or None,
        "is_platform_binary": p.get("is_platform_binary"),
        "tty.path": at(p, "tty/path"),
        "responsible_audit_token.pid": at(p, "responsible_audit_token/pid"),
        "group_id": p.get("group_id"),
        "start_time": (p.get("start_time") or "")[:19],
    }


def destination(b):
    p = at(b, "destination/existing_file/path")
    if p is not None:
        return p
    d, n = at(b, "destination/new_path/dir/path"), at(b, "destination/new_path/filename")
    return None if d is None or n is None else d.rstrip("/") + "/" + n


def prune(v):
    """An event's body as the plugin passes it on: without the stat blocks."""
    if isinstance(v, dict):
        return {k: prune(x) for k, x in v.items() if k != "stat"}
    if isinstance(v, list):
        return [prune(x) for x in v]
    return v


def subset(mine, theirs, path, out):
    """Every key the sensor wrote, against eslogger's; and which it left out."""
    if isinstance(mine, dict) and isinstance(theirs, dict):
        for k in theirs:
            if k not in mine:
                out["missing:" + path + k] += 1
        for k, v in mine.items():
            if k not in theirs:
                out["extra:" + path + k] += 1
            else:
                subset(v, theirs[k], path + k + ".", out)
    elif mine != theirs:
        out["differs:" + path.rstrip(".")] += 1


def read(r):
    """What the plugin reads of a line, flat."""
    kind, body = next(iter(r["event"].items()))
    f = {"time": r.get("time")}
    for k, v in (proc(r.get("process")) or {}).items():
        f["process." + k] = v
    if kind == "exec":
        for k, v in (proc(body.get("target")) or {}).items():
            f["exec.target." + k] = v
        f["exec.args"] = body.get("args")
        f["exec.env"] = body.get("env")
        f["exec.script.path"] = at(body, "script/path")
        f["exec.cwd.path"] = at(body, "cwd/path")
    elif kind == "fork":
        for k, v in (proc(body.get("child")) or {}).items():
            f["fork.child." + k] = v
    elif kind == "open":
        f["open.file.path"] = at(body, "file/path")
        f["open.fflag"] = body.get("fflag")
    elif kind == "close":
        f["close.modified"] = body.get("modified")
        f["close.target.path"] = at(body, "target/path")
    elif kind == "create":
        f["create.destination"] = destination(body)
    elif kind == "rename":
        f["rename.source.path"] = at(body, "source/path")
        f["rename.destination"] = destination(body)
        f["rename.existing_file"] = at(body, "destination/existing_file") is not None
    elif kind == "unlink":
        f["unlink.target.path"] = at(body, "target/path")
    elif kind == "exit":
        pass
    return kind, f


def load(path):
    rows, bad = [], 0
    with open(path, "rb") as fh:
        for line in fh:
            try:
                r = json.loads(line)
                kind = next(iter(r["event"]))
                rows.append((r["time"], kind, at(r, "process/audit_token/pid"), r))
            except Exception:
                bad += 1
    return rows, bad


def main(d):
    es, es_bad = load(d + "/eslogger.ndjson")
    se, se_bad = load(d + "/sensor.ndjson")
    print(f"eslogger: {len(es)} lines read, {es_bad} unreadable (a cut last line is expected)")
    print(f"sensor:   {len(se)} lines read, {se_bad} unreadable")
    if not es or not se:
        return
    # the window both were running in, a second in from each edge
    lo = max(es[0][0], se[0][0])
    hi = min(es[-1][0], se[-1][0])
    lo = lo[:19] + ".999999999Z"
    hi = hi[:19] + ".000000000Z"
    es = [x for x in es if lo < x[0] < hi]
    se = [x for x in se if lo < x[0] < hi]
    print(f"in the window both ran: eslogger {len(es)}, sensor {len(se)}")

    def by_key(rows):
        m = collections.defaultdict(list)
        for t, k, pid, r in rows:
            m[(t, k, pid)].append(r)
        return m

    a, b = by_key(es), by_key(se)
    kinds = collections.Counter()
    only_es, only_se = collections.Counter(), collections.Counter()
    differs, same, compared = collections.Counter(), 0, 0
    other = collections.Counter()
    for key in set(a) | set(b):
        ra, rb = a.get(key, []), b.get(key, [])
        kind = key[1]
        if len(ra) > len(rb):
            only_es[kind] += len(ra) - len(rb)
        if len(rb) > len(ra):
            only_se[kind] += len(rb) - len(ra)
        for x, y in zip(ra, rb):
            compared += 1
            kinds[kind] += 1
            _, fx = read(x)
            _, fy = read(y)
            bad = [k for k in fx if fx[k] != fy.get(k)]
            if kind in ("btm_launch_item_add", "tcc_modify"):
                subset(prune(y["event"][kind]), prune(x["event"][kind]), kind + ".", other)
            if bad:
                for k in bad:
                    differs[f"{kind}: {k}"] += 1
            else:
                same += 1
    print(f"matched by time, kind and pid: {compared} events; all read fields equal in {same}")
    print("matched, by kind:", dict(kinds.most_common()))
    print("only in eslogger, by kind:", dict(only_es) or "none")
    print("only in sensor, by kind:", dict(only_se) or "none")
    print("fields that differ (event kind: field, count):")
    for k, n in differs.most_common(40):
        print(f"  {k}: {n}")
    if not differs:
        print("  none")
    if other:
        print("launch item and TCC bodies, sensor against eslogger:")
        for k, n in other.most_common(40):
            print(f"  {k}: {n}")
    print(
        "size: eslogger %.1f MB, sensor %.1f MB"
        % (os.path.getsize(d + "/eslogger.ndjson") / 1e6, os.path.getsize(d + "/sensor.ndjson") / 1e6)
    )


if __name__ == "__main__":
    main(sys.argv[1].rstrip("/"))
