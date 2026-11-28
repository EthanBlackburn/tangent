// app.swift: native macOS companion window for Tangent (`Tangent.app`).
//
// Designed as a quiet native instrument — frameless unified titlebar over a
// translucent vibrancy sidebar, crisp editorial reading canvas for flagged
// activity, and a clean grouped settings list for models and macOS Keychain
// API keys. Zero third-party dependencies; targets macOS 13.0+.

import AppKit
import Foundation
import SwiftUI

// MARK: data models

struct ProviderEnvVar: Identifiable, Hashable {
    var id: String { name }
    let name: String
    let description: String
    let required: Bool
    let secret: Bool
    let isSet: Bool
    let value: String?

    static func parse(_ dict: [String: Any]) -> ProviderEnvVar? {
        guard let name = dict["name"] as? String, !name.isEmpty else { return nil }
        return ProviderEnvVar(
            name: name,
            description: dict["description"] as? String ?? "",
            required: dict["required"] as? Bool ?? true,
            secret: dict["secret"] as? Bool ?? true,
            isSet: dict["set"] as? Bool ?? false,
            value: dict["value"] as? String
        )
    }
}

/// How long an alert may wait before its review is taken for lost: longer
/// than the slowest review, with the queue ahead of it.
let reviewsWithin: TimeInterval = 15 * 60

extension ISO8601DateFormatter {
    /// An RFC 3339 time, with fractional seconds or without.
    static func flexible(_ text: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: text) ?? ISO8601DateFormatter().date(from: text)
    }
}

enum FlaggedKind: String, Hashable {
    case malicious
    case unresolved
    case benign
    case failed
    case reviewing
    /// Nobody checked it: the judge could not be asked about the session,
    /// or it flagged it and no review came within any review's time.
    case unreviewed

    var label: String {
        switch self {
        case .malicious: return "Malicious"
        case .unresolved: return "Needs a look"
        case .benign: return "Cleared"
        case .failed: return "Review failed"
        case .reviewing: return "Reviewing"
        case .unreviewed: return "Unchecked"
        }
    }

    var isAlert: Bool {
        self == .malicious || self == .unresolved || self == .failed || self == .unreviewed
    }

    var dotColor: Color {
        switch self {
        case .malicious: return Theme.crimson
        case .unresolved, .failed, .unreviewed: return Theme.amber
        case .reviewing: return Theme.inkSecondary
        case .benign: return Color(nsColor: .tertiaryLabelColor)
        }
    }

    var symbol: String {
        switch self {
        case .malicious: return "exclamationmark.octagon.fill"
        case .unresolved: return "exclamationmark.triangle.fill"
        case .failed, .unreviewed: return "exclamationmark.circle.fill"
        case .reviewing: return "sparkle"
        case .benign: return "checkmark.circle"
        }
    }
}

/// One thing the reviewer asked for in a turn, and the start of what it got.
struct ReviewCall: Equatable {
    let tool: String
    /// the SQL of a query, the path of a file read
    let asked: String
    let result: String
    let failed: Bool
}

/// One turn of a review: the reasoning the reviewer showed, what it said,
/// and what it asked for.
struct ReviewStep: Equatable {
    var thinking: String
    var said: String
    var calls: [ReviewCall]
}

private func reviewCall(tool: String, arguments: [String: Any], result: String, failed: Bool) -> ReviewCall {
    ReviewCall(
        tool: tool,
        asked: (arguments["sql"] as? String) ?? (arguments["path"] as? String) ?? "",
        result: result,
        failed: failed
    )
}

/// A finished review's turns, as its record keeps them (`steps`).
func reviewSteps(record obj: [String: Any]) -> [ReviewStep] {
    (obj["steps"] as? [[String: Any]] ?? []).map { step in
        ReviewStep(
            thinking: step["thinking"] as? String ?? "",
            said: step["said"] as? String ?? "",
            calls: (step["calls"] as? [[String: Any]] ?? []).map {
                reviewCall(tool: $0["tool"] as? String ?? "", arguments: $0,
                           result: $0["result"] as? String ?? "", failed: $0["failed"] as? Bool ?? false)
            }
        )
    }
}

/// The turns of reviews in progress, by session and window, from the end of
/// agent.ndjson, which the watcher writes a line to as each turn happens.
/// Only the conversation last begun for a key: one begun again starts over.
func liveReviewSteps(dir: String) -> [String: [ReviewStep]] {
    let path = (dir as NSString).appendingPathComponent("agent.ndjson")
    guard let file = FileHandle(forReadingAtPath: path) else { return [:] }
    defer { try? file.close() }
    let size = (try? file.seekToEnd()) ?? 0
    let tail: UInt64 = 2 << 20
    try? file.seek(toOffset: size > tail ? size - tail : 0)
    guard let data = try? file.readToEnd() else { return [:] }
    var live: [String: [ReviewStep]] = [:]
    for raw in data.split(separator: UInt8(ascii: "\n")) {
        guard let obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
              let key = obj["trace"] as? String else { continue }
        switch obj["kind"] as? String ?? "" {
        case "asked":
            if obj["first"] as? Bool == true { live[key] = [] }
        case "turn":
            let calls = (obj["calls"] as? [[String: Any]] ?? []).map {
                reviewCall(tool: $0["name"] as? String ?? "", arguments: $0["arguments"] as? [String: Any] ?? [:],
                           result: "", failed: false)
            }
            live[key, default: []].append(ReviewStep(
                thinking: obj["thinking"] as? String ?? "", said: obj["said"] as? String ?? "", calls: calls))
        case "results":
            // what the last turn's calls were given back, in their order
            guard var steps = live[key], var last = steps.popLast() else { continue }
            let results = obj["results"] as? [[String: Any]] ?? []
            last.calls = last.calls.enumerated().map { i, call in
                guard i < results.count else { return call }
                return ReviewCall(tool: call.tool, asked: call.asked,
                                  result: results[i]["text"] as? String ?? "",
                                  failed: results[i]["failed"] as? Bool ?? false)
            }
            steps.append(last)
            live[key] = steps
        case "error":
            live[key, default: []].append(ReviewStep(
                thinking: "", said: "The model failed: \(obj["error"] as? String ?? "")", calls: []))
        default:
            continue
        }
    }
    return live
}

struct FlaggedEntry: Identifiable, Equatable {
    let id: String
    let ts: String
    let kind: FlaggedKind
    let subject: String
    let who: String
    let sessionId: String
    let summary: String
    let finding: String
    let check: String
    let judgeMark: String
    let judgeNote: String
    let feedbackKey: String
    let feedbackFile: String?
    let feedbackLineJSON: String?
    /// The reviewer's turns: a finished review's, or one in progress so far.
    var steps: [ReviewStep] = []

    static func == (lhs: FlaggedEntry, rhs: FlaggedEntry) -> Bool {
        lhs.id == rhs.id && lhs.kind == rhs.kind && lhs.ts == rhs.ts && lhs.finding == rhs.finding
            && lhs.steps == rhs.steps
    }
}

enum AppTab: String, CaseIterable {
    case activity = "Activity"
    case models = "Models & Keys"
    case health = "Health"
}

enum ActivityFilter: String, CaseIterable {
    case alerts = "Alerts"
    case all = "All"
    case unreviewed = "Unreviewed"
}

// MARK: adaptive color tokens

private enum Theme {
    private static func dynamic(light: UInt32, dark: UInt32, lightAlpha: CGFloat = 1, darkAlpha: CGFloat = 1) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let hex = isDark ? dark : light
            let alpha = isDark ? darkAlpha : lightAlpha
            let r = CGFloat((hex >> 16) & 0xFF) / 255.0
            let g = CGFloat((hex >> 8) & 0xFF) / 255.0
            let b = CGFloat(hex & 0xFF) / 255.0
            return NSColor(srgbRed: r, green: g, blue: b, alpha: alpha)
        })
    }

    static let canvas = dynamic(light: 0xFFFFFF, dark: 0x131417)
    static let surface = dynamic(light: 0xF5F6F8, dark: 0x1B1C20)
    static let surfaceHover = dynamic(light: 0xECEEF2, dark: 0x23252B)
    static let selection = dynamic(light: 0x000000, dark: 0xFFFFFF, lightAlpha: 0.065, darkAlpha: 0.095)
    static let hairline = dynamic(light: 0x000000, dark: 0xFFFFFF, lightAlpha: 0.075, darkAlpha: 0.08)
    static let hairlineStrong = dynamic(light: 0x000000, dark: 0xFFFFFF, lightAlpha: 0.13, darkAlpha: 0.14)
    static let codeBg = dynamic(light: 0x000000, dark: 0xFFFFFF, lightAlpha: 0.055, darkAlpha: 0.075)

    static let ink = dynamic(light: 0x111318, dark: 0xF3F4F6)
    static let inkSecondary = dynamic(light: 0x5B6370, dark: 0x8E95A2)
    static let inkTertiary = dynamic(light: 0x8C94A3, dark: 0x5D636F)

    static let primaryBtnBg = dynamic(light: 0x18191D, dark: 0xF3F4F6)
    static let primaryBtnFg = dynamic(light: 0xFFFFFF, dark: 0x131417)

    static let emerald = dynamic(light: 0x059669, dark: 0x34D399)
    static let crimson = dynamic(light: 0xE11D48, dark: 0xF43F5E)
    static let amber = dynamic(light: 0xD97706, dark: 0xF59E0B)
}

/// Renders incident prose with inline filesystem paths (`~/...`, `/Library/...`)
/// and backticked spans cleanly set in SF Mono so commands and paths pop at a
/// glance without adding visual clutter.
private func formattedBriefText(_ text: String, baseSize: CGFloat, color: Color) -> AttributedString {
    var result = AttributedString()
    let pattern = #"`([^`]+)`|((?:~/|/(?:Applications|Users|Library|System|Volumes|private|tmp|var|etc|opt|usr|bin|sbin)/)[^\s,;()\"']+)"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
        var plain = AttributedString(text)
        plain.font = .system(size: baseSize, weight: .regular)
        plain.foregroundColor = color
        return plain
    }

    let nsText = text as NSString
    let matches = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
    var cursor = 0

    func appendPlain(_ s: String) {
        guard !s.isEmpty else { return }
        var part = AttributedString(s)
        part.font = .system(size: baseSize, weight: .regular)
        part.foregroundColor = color
        result.append(part)
    }

    func appendCode(_ s: String) {
        guard !s.isEmpty else { return }
        var part = AttributedString("\u{200A}\(s)\u{200A}")
        part.font = .system(size: baseSize - 1.5, weight: .medium, design: .monospaced)
        part.foregroundColor = Theme.ink
        part.backgroundColor = Theme.codeBg
        result.append(part)
    }

    for match in matches {
        let range = match.range
        if range.location > cursor {
            appendPlain(nsText.substring(with: NSRange(location: cursor, length: range.location - cursor)))
        }
        let innerRange = match.range(at: 1).location != NSNotFound ? match.range(at: 1) : match.range(at: 2)
        var token = nsText.substring(with: innerRange)
        var trailing = ""
        // Keep trailing sentence punctuation outside the monospace span.
        while let last = token.last, last == "." || last == ":" {
            trailing.insert(last, at: trailing.startIndex)
            token.removeLast()
        }
        appendCode(token)
        if !trailing.isEmpty { appendPlain(trailing) }
        cursor = range.location + range.length
    }
    if cursor < nsText.length {
        appendPlain(nsText.substring(from: cursor))
    }
    return result
}

// MARK: native vibrancy helper

private struct VisualEffectSurface: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}

/// Tangent's geometric chevron emblem rendered cleanly in SwiftUI at any scale.
private struct TangentMark: View {
    var size: CGFloat = 18

    var body: some View {
        Canvas { ctx, canvasSize in
            let sx = canvasSize.width / 18.0
            let sy = canvasSize.height / 18.0
            func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * sx, y: y * sy) }

            var top = Path()
            top.move(to: pt(2.4, 10.7))
            top.addLine(to: pt(8.9, 5.7))
            top.addLine(to: pt(6.1, 3.5))
            top.addLine(to: pt(7.6, 2.3))
            top.addLine(to: pt(16.0, 8.8))
            top.addLine(to: pt(14.5, 10.0))
            top.addLine(to: pt(11.4, 7.6))
            top.addLine(to: pt(4.8, 12.7))
            top.closeSubpath()
            ctx.fill(top, with: .foreground)

            var bottom = Path()
            bottom.move(to: pt(2.4, 13.7))
            bottom.addLine(to: pt(5.0, 15.7))
            bottom.addLine(to: pt(11.4, 10.8))
            bottom.addLine(to: pt(14.5, 13.2))
            bottom.addLine(to: pt(16.0, 12.0))
            bottom.addLine(to: pt(11.4, 8.5))
            bottom.addLine(to: pt(4.8, 13.6))
            bottom.addLine(to: pt(3.6, 12.7))
            bottom.closeSubpath()
            ctx.fill(bottom, with: .foreground)
        }
        .frame(width: size, height: size)
    }
}

// MARK: non-secret service.json persistence (matches crates/cli/src/service.rs)

enum ServiceConfigStore {
    static func servicePath(in dir: String) -> String {
        (dir as NSString).appendingPathComponent("service.json")
    }

    static func updateNonSecret(key: String, value: String, in dir: String) throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = servicePath(in: dir)
        var root: [String: Any] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let existing = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
            root = existing
        }
        var env = root["env"] as? [String: String] ?? [:]
        let clean = value
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        if clean.isEmpty {
            env.removeValue(forKey: key)
        } else {
            env[key] = clean
        }
        root["env"] = env
        let out = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        var finalData = out
        finalData.append(0x0A)
        try finalData.write(to: URL(fileURLWithPath: path), options: .atomic)
    }
}

// MARK: NDJSON history loader (reviews.ndjson + pending alerts.ndjson)

private func cleanInlineText(_ s: String) -> String {
    let replaced = s.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }.joined()
    return replaced.split(whereSeparator: \.isWhitespace).joined(separator: " ")
}

private func firstSentenceSnippet(_ text: String, limit: Int = 100) -> String {
    if let range = text.range(of: ". ") {
        let first = String(text[..<range.upperBound]).trimmingCharacters(in: .whitespaces)
        if first.count <= limit { return first }
    }
    if text.count <= limit { return text }
    return String(text.prefix(limit)).trimmingCharacters(in: .whitespaces) + "…"
}

private func formatExactTime(_ rfc3339: String) -> String {
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = iso.date(from: rfc3339) ?? ISO8601DateFormatter().date(from: rfc3339)
    guard let date else { return rfc3339 }
    let out = DateFormatter()
    out.dateStyle = .medium
    out.timeStyle = .short
    return out.string(from: date)
}

/// Loads up to `maxEntries` most recent flagged/reviewed records from
/// `reviews.ndjson` and any still-unsettled alerts from `alerts.ndjson`.
func loadFlaggedHistory(in dir: String, maxEntries: Int = 400) -> [FlaggedEntry] {
    var entries: [FlaggedEntry] = []
    var reviewedKeys = Set<String>()

    let reviewsPath = (dir as NSString).appendingPathComponent("reviews.ndjson")
    if let text = try? String(contentsOfFile: reviewsPath, encoding: .utf8) {
        let lines = text.split(separator: "\n")
        for (idx, raw) in lines.reversed().enumerated() {
            if entries.count >= maxEntries { break }
            guard let data = raw.data(using: .utf8),
                  let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            else { continue }
            let source = obj["source"] as? String ?? ""
            let isReview = obj["reviewed"] != nil || source == "macos_review"
            guard isReview else { continue }

            let ts = obj["ts"] as? String ?? ""
            let session = obj["session"] as? [String: Any]
            let sid = session?["id"] as? String ?? ""
            let window = session?["window"] as? String ?? ""
            let entryPath = session?["entry"] as? String ?? ""
            let normActor = (obj["_norm"] as? [String: Any])?["actor"] as? String ?? ""
            let who = cleanInlineText(!normActor.isEmpty ? normActor : entryPath)
            let subject: String = {
                if !entryPath.isEmpty {
                    let base = (entryPath as NSString).lastPathComponent
                    if !base.isEmpty { return cleanInlineText(base) }
                }
                return who.isEmpty ? "Unknown" : who
            }()

            let review = obj["review"] as? [String: Any] ?? [:]
            let revError = cleanInlineText(review["error"] as? String ?? "")
            let verdict = review["verdict"] as? String ?? ""
            let kind: FlaggedKind
            if !revError.isEmpty {
                kind = .failed
            } else {
                switch verdict {
                case "malicious": kind = .malicious
                case "unresolved": kind = .unresolved
                case "benign": kind = .benign
                default: kind = .unresolved
                }
            }

            let finding = cleanInlineText(!revError.isEmpty ? revError : (review["finding"] as? String ?? ""))
            let check = cleanInlineText(review["check"] as? String ?? "")
            let judge = obj["judge"] as? [String: Any] ?? [:]
            let judgeMark = judge["warrants_investigation"] as? String ?? (judge["flag"] as? Bool == true ? "flag" : "")
            let judgeNote = cleanInlineText((judge["why"] as? String) ?? (judge["assessment"] as? String) ?? "")

            let isMac = (source == "macos_review")
            let feedbackFile = isMac ? (dir as NSString).appendingPathComponent("feedback.ndjson") : nil
            var feedbackLineJSON: String? = nil
            if isMac {
                var fb: [String: Any] = ["source": "macos_feedback", "reviewed": ts]
                if let session { fb["session"] = session }
                if let jm = judge["warrants_investigation"] { fb["judge"] = jm }
                if let rv = review["verdict"] { fb["review"] = rv }
                if let fbData = try? JSONSerialization.data(withJSONObject: fb) {
                    feedbackLineJSON = String(decoding: fbData, as: UTF8.self)
                }
            }

            if !sid.isEmpty {
                reviewedKeys.insert("\(sid)|\(window)")
                reviewedKeys.insert(sid)
            }
            let feedbackKey = "\(sid)|\(ts)"
            entries.append(FlaggedEntry(
                id: "rev-\(idx)-\(sid)-\(ts)",
                ts: ts,
                kind: kind,
                subject: subject,
                who: who,
                sessionId: sid,
                summary: firstSentenceSnippet(finding.isEmpty ? judgeNote : finding),
                finding: finding,
                check: check,
                judgeMark: judgeMark,
                judgeNote: judgeNote,
                feedbackKey: feedbackKey,
                feedbackFile: feedbackFile,
                feedbackLineJSON: feedbackLineJSON,
                steps: reviewSteps(record: obj)
            ))
        }
    }

    // Add recent unsettled Tier 1 alerts at the top as `Reviewing`.
    let alertsPath = (dir as NSString).appendingPathComponent("alerts.ndjson")
    if let text = try? String(contentsOfFile: alertsPath, encoding: .utf8) {
        // Read once, and only if a session the judge could not be asked
        // about is among them: when each session was last judged.
        var judgedAt: [String: String]? = nil
        let live = liveReviewSteps(dir: dir)
        let recentAlertLines = text.split(separator: "\n").suffix(40).reversed()
        var pending: [FlaggedEntry] = []
        var seenPending = Set<String>()
        for (idx, raw) in recentAlertLines.enumerated() {
            guard let data = raw.data(using: .utf8),
                  let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            else { continue }
            let session = obj["session"] as? [String: Any]
            let sid = session?["id"] as? String ?? ""
            let window = session?["window"] as? String ?? ""
            let key = !window.isEmpty ? "\(sid)|\(window)" : sid
            if !key.isEmpty && (reviewedKeys.contains(key) || seenPending.contains(key)) { continue }
            if !key.isEmpty { seenPending.insert(key) }

            let ts = obj["ts"] as? String ?? ""
            let entryPath = session?["entry"] as? String ?? ""
            let normActor = (obj["_norm"] as? [String: Any])?["actor"] as? String ?? ""
            let who = cleanInlineText(!normActor.isEmpty ? normActor : entryPath)
            let subject = !entryPath.isEmpty ? cleanInlineText((entryPath as NSString).lastPathComponent) : (who.isEmpty ? "Unknown" : who)
            let judge = obj["judge"] as? [String: Any] ?? [:]
            let judgeMark = judge["warrants_investigation"] as? String ?? "flag"
            let judgeNote = cleanInlineText((judge["why"] as? String) ?? (judge["assessment"] as? String) ?? "")

            // A review is over within minutes, with a verdict or an error.
            // An alert still without one after that was dropped on the way
            // (the watcher was stopped while it waited), and is not being
            // reviewed: it is said so, not left "Reviewing" for good.
            let flaggedAt = ISO8601DateFormatter.flexible(ts)
            let waited = flaggedAt.map { Date().timeIntervalSince($0) } ?? 0
            // A session the judge could not be asked about is with the
            // alerts so that it is seen, and is never reviewed: there is no
            // verdict to review. It is said at once, with the model's error.
            let judgeError = cleanInlineText(judge["error"] as? String ?? "")
            // One the judge has answered for since is no longer unchecked:
            // its answer covers the session so far, and it is not shown.
            if !judgeError.isEmpty {
                if judgedAt == nil { judgedAt = lastJudged(dir: dir) }
                if let later = judgedAt?[sid], later > ts { continue }
            }
            let dropped = !judgeError.isEmpty || waited > reviewsWithin
            let unreviewedNote = judgeError.isEmpty
                ? "The judge flagged this session and no review of it was finished, so nobody has looked into it."
                : "The model could not be asked about this session, so it was never checked. It is not a finding.\n\n\(judgeError)"
            pending.append(FlaggedEntry(
                id: "alert-\(idx)-\(sid)-\(ts)",
                ts: ts,
                kind: dropped ? .unreviewed : .reviewing,
                subject: subject,
                who: who,
                sessionId: sid,
                summary: firstSentenceSnippet(judgeNote.isEmpty
                    ? (!judgeError.isEmpty ? "Not checked: the model could not be reached"
                        : (dropped ? "Flagged by judge, never reviewed" : "Flagged by judge, awaiting review…"))
                    : judgeNote),
                finding: judgeNote.isEmpty
                    ? (dropped ? unreviewedNote : "Flagged by the first-pass judge. The reviewer is investigating this session against the local Parquet log.")
                    // the judge's note is shown once, under its own heading
                    : (dropped ? unreviewedNote : judgeNote),
                check: "",
                judgeMark: judgeMark,
                judgeNote: judgeNote,
                feedbackKey: "\(sid)|\(ts)",
                feedbackFile: nil,
                feedbackLineJSON: nil,
                steps: dropped ? [] : (live["\(sid)|\(window)"] ?? [])
            ))
            if pending.count >= 15 { break }
        }
        entries.insert(contentsOf: pending, at: 0)
    }

    return entries
}

/// When each session was last judged with an answer, by its id, from the end
/// of verdicts.ndjson: the last few megabytes, which is hours of a Mac's
/// sessions. The file has every verdict there has been and is not read whole.
private func lastJudged(dir: String) -> [String: String] {
    let path = (dir as NSString).appendingPathComponent("verdicts.ndjson")
    guard let file = FileHandle(forReadingAtPath: path) else { return [:] }
    defer { try? file.close() }
    let size = (try? file.seekToEnd()) ?? 0
    let tail: UInt64 = 4 << 20
    try? file.seek(toOffset: size > tail ? size - tail : 0)
    guard let data = try? file.readToEnd() else { return [:] }
    var judged: [String: String] = [:]
    // the first line may be the end of one cut in two, and does not parse
    for raw in data.split(separator: UInt8(ascii: "\n")) {
        guard let obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
              let judge = obj["judge"] as? [String: Any], judge["error"] == nil,
              let session = obj["session"] as? [String: Any],
              let sid = session["id"] as? String, !sid.isEmpty,
              let ts = obj["ts"] as? String
        else { continue }
        if ts > (judged[sid] ?? "") { judged[sid] = ts }
    }
    return judged
}

// MARK: shared observable store

final class TangentStore: ObservableObject {
    let watchDir: String
    let tangentBin: String

    @Published var status: WatchStatus?
    @Published var choices: [ModelChoice] = []
    @Published var answered: [String: String] = [:]
    @Published var events: [FlaggedEntry] = []
    @Published var busyAction: String?
    @Published var lastErrorMessage: String?

    @Published var selectedTab: AppTab = .activity
    @Published var filter: ActivityFilter = .alerts
    @Published var searchText: String = ""
    @Published var selectedEventId: String?
    @Published var keySheetChoice: ModelChoice?

    var onRunCLI: (([String], String) -> Void)?
    var onSimulate: ((String) -> Void)?
    var onOpenFDA: (() -> Void)?
    var onOpenLog: (() -> Void)?
    var onOpenFolder: (() -> Void)?
    var onCopyStatus: (() -> Void)?
    var onReloadRequested: (() -> Void)?

    init(watchDir: String, tangentBin: String) {
        self.watchDir = watchDir
        self.tangentBin = tangentBin
    }

    var isAlive: Bool { status?.isAlive ?? false }
    var needsFda: Bool { status?.needsFda ?? false }
    var authError: String? {
        guard isAlive, let err = status?.authError, !err.isEmpty else { return nil }
        return err
    }

    var currentChoice: ModelChoice? {
        choices.first(where: { $0.current })
    }

    var unreviewedAlertCount: Int {
        events.filter { $0.kind.isAlert && answered[$0.feedbackKey] == nil }.count
    }

    var filteredEvents: [FlaggedEntry] {
        let base: [FlaggedEntry]
        switch filter {
        case .alerts:
            base = events.filter { $0.kind.isAlert || $0.kind == .reviewing }
        case .all:
            base = events
        case .unreviewed:
            base = events.filter { $0.kind.isAlert && answered[$0.feedbackKey] == nil }
        }
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return base }
        return base.filter {
            $0.subject.lowercased().contains(q)
                || $0.who.lowercased().contains(q)
                || $0.finding.lowercased().contains(q)
                || $0.check.lowercased().contains(q)
                || $0.judgeNote.lowercased().contains(q)
        }
    }

    var selectedEvent: FlaggedEntry? {
        if let id = selectedEventId, let found = filteredEvents.first(where: { $0.id == id }) {
            return found
        }
        return filteredEvents.first
    }

    func reloadHistory() {
        let dir = watchDir
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let loaded = loadFlaggedHistory(in: dir)
            DispatchQueue.main.async {
                guard let self else { return }
                self.events = loaded
                if self.selectedEventId == nil {
                    self.selectedEventId = self.filteredEvents.first?.id
                }
            }
        }
    }

    func selectAlert(matchingSubjectOrTs ts: String, subject: String) {
        selectedTab = .activity
        filter = .alerts
        if let hit = events.first(where: { (!ts.isEmpty && $0.ts == ts) || (!subject.isEmpty && ($0.subject == subject || $0.who == subject)) }) {
            selectedEventId = hit.id
        } else {
            let dir = watchDir
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let loaded = loadFlaggedHistory(in: dir)
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.events = loaded
                    if let hit = loaded.first(where: { (!ts.isEmpty && $0.ts == ts) || (!subject.isEmpty && ($0.subject == subject || $0.who == subject)) }) {
                        self.selectedEventId = hit.id
                    } else {
                        self.selectedEventId = self.filteredEvents.first?.id
                    }
                }
            }
        }
    }

    func recordFeedback(_ answer: String, for entry: FlaggedEntry) {
        guard let file = entry.feedbackFile, let lineJSON = entry.feedbackLineJSON else { return }
        keep(answer, for: ["file": file, "line": lineJSON])
        answered[entry.feedbackKey] = answer
        onReloadRequested?()
    }

    func saveKeyAndActivate(choice: ModelChoice, values: [String: String], activate: Bool) {
        do {
            for envVar in choice.envVars {
                guard let raw = values[envVar.name] else { continue }
                let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                if envVar.secret {
                    if !trimmed.isEmpty {
                        try KeychainStore.set(account: envVar.name, value: trimmed)
                    }
                } else {
                    try ServiceConfigStore.updateNonSecret(key: envVar.name, value: trimmed, in: watchDir)
                }
            }
            lastErrorMessage = nil
            keySheetChoice = nil
            if activate {
                onRunCLI?(choice.args, "Switching to \(choice.name)…")
            } else {
                onReloadRequested?()
            }
        } catch {
            lastErrorMessage = "Could not save credentials: \(error.localizedDescription)"
        }
    }

    func clearKeys(for choice: ModelChoice) {
        do {
            for envVar in choice.envVars {
                if envVar.secret {
                    try KeychainStore.clear(account: envVar.name)
                } else {
                    try ServiceConfigStore.updateNonSecret(key: envVar.name, value: "", in: watchDir)
                }
            }
            lastErrorMessage = nil
            keySheetChoice = nil
            onReloadRequested?()
        } catch {
            lastErrorMessage = "Could not clear credentials: \(error.localizedDescription)"
        }
    }
}

// MARK: Root Shell (Frameless Unified Titlebar + Vibrancy Sidebar + Calm Reading Canvas)

struct TangentAppView: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        HStack(spacing: 0) {
            SidebarColumn(store: store)
                .frame(width: 286)

            Rectangle()
                .fill(Theme.hairline)
                .frame(width: 1)

            ZStack {
                Theme.canvas.ignoresSafeArea()
                VStack(spacing: 0) {
                    ActionBannerStrip(store: store)
                    Group {
                        switch store.selectedTab {
                        case .activity:
                            ActivityDetailStage(store: store)
                        case .models:
                            ModelsAndKeysStage(store: store)
                        case .health:
                            HealthStage(store: store)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minWidth: 520, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 820, minHeight: 540)
        .ignoresSafeArea(.container, edges: .top)
        .sheet(item: $store.keySheetChoice) { choice in
            KeyEditorSheet(store: store, choice: choice)
        }
    }
}

// MARK: Vibrancy Sidebar

private struct SidebarColumn: View {
    @ObservedObject var store: TangentStore
    @State private var pulse = false

    var body: some View {
        ZStack {
            VisualEffectSurface(material: .sidebar, blendingMode: .behindWindow)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                // Space for macOS traffic light buttons
                Spacer().frame(height: 36)

                // Brand + live pulse header
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 9) {
                        TangentMark(size: 18)
                            .foregroundColor(Theme.ink)
                        Text("Tangent")
                            .font(.system(size: 15, weight: .semibold))
                            .tracking(-0.2)
                            .foregroundColor(Theme.ink)
                        Spacer()
                        liveStatusPill
                    }

                    // Primary navigation
                    VStack(spacing: 2) {
                        SidebarNavButton(
                            title: "Activity",
                            symbol: "waveform.path.ecg",
                            badgeCount: store.unreviewedAlertCount,
                            badgeColor: Theme.crimson,
                            isSelected: store.selectedTab == .activity,
                            shortcutKey: "1"
                        ) {
                            store.selectedTab = .activity
                        }

                        SidebarNavButton(
                            title: "Models & Keys",
                            symbol: "key.horizontal",
                            badgeCount: store.authError != nil ? 1 : 0,
                            badgeColor: Theme.amber,
                            isSelected: store.selectedTab == .models,
                            shortcutKey: "2"
                        ) {
                            store.selectedTab = .models
                        }

                        SidebarNavButton(
                            title: "Health",
                            symbol: "heart.text.square",
                            badgeCount: store.needsFda || (store.isAlive && !sensorConnected()) ? 1 : 0,
                            badgeColor: Theme.amber,
                            isSelected: store.selectedTab == .health,
                            shortcutKey: "3"
                        ) {
                            store.selectedTab = .health
                        }
                    }
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 12)

                Rectangle()
                    .fill(Theme.hairline)
                    .frame(height: 1)

                // Contextual lower sidebar: Activity stream or live stats summary
                if store.selectedTab == .activity {
                    ActivitySidebarList(store: store)
                } else {
                    ModelsSidebarSummary(store: store)
                }

                Rectangle()
                    .fill(Theme.hairline)
                    .frame(height: 1)

                // Quiet bottom controls
                HStack(spacing: 8) {
                    Button {
                        if store.isAlive {
                            store.onRunCLI?(["down"], "Pausing…")
                        } else {
                            store.onRunCLI?(["up"], "Starting…")
                        }
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: store.isAlive ? "pause.fill" : "play.fill")
                                .font(.system(size: 10, weight: .semibold))
                            Text(store.isAlive ? "Pause" : "Resume")
                                .font(.system(size: 12, weight: .medium))
                        }
                        .foregroundColor(Theme.ink)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Theme.surface.opacity(0.75))
                        .cornerRadius(6)
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Theme.hairlineStrong, lineWidth: 1))
                    }
                    .buttonStyle(.plain)
                    .disabled(store.busyAction != nil)

                    Spacer()

                    Menu {
                        Button("AI coding agent takeover") { store.onSimulate?("agent") }
                        Button("Credentials sweep") { store.onSimulate?("credentials") }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "bolt.shield")
                                .font(.system(size: 11))
                            Text("Simulate")
                                .font(.system(size: 12, weight: .medium))
                        }
                        .foregroundColor(Theme.inkSecondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 5)
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
            }
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 2.2).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }

    private var liveStatusPill: some View {
        HStack(spacing: 6) {
            ZStack {
                if store.isAlive && !store.needsFda && store.authError == nil {
                    Circle()
                        .fill(statusColor.opacity(pulse ? 0.12 : 0.30))
                        .frame(width: pulse ? 14 : 10, height: pulse ? 14 : 10)
                }
                Circle()
                    .fill(statusColor)
                    .frame(width: 7, height: 7)
            }
            .frame(width: 14, height: 14)

            Text(statusWord)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundColor(Theme.inkSecondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Theme.surface.opacity(0.65))
        .cornerRadius(99)
        .overlay(Capsule().stroke(Theme.hairline, lineWidth: 1))
    }

    private var statusColor: Color {
        if store.busyAction != nil { return Theme.amber }
        if store.needsFda || store.authError != nil { return Theme.amber }
        if store.isAlive { return Theme.emerald }
        return Theme.inkTertiary
    }

    private var statusWord: String {
        if let busy = store.busyAction { return busy }
        if store.needsFda { return "Needs access" }
        if let err = store.authError { return AuthProblem(err).short }
        if store.isAlive {
            return store.status?.state == "starting" ? "Starting" : "Watching"
        }
        return "Paused"
    }
}

private struct SidebarNavButton: View {
    let title: String
    let symbol: String
    let badgeCount: Int
    let badgeColor: Color
    let isSelected: Bool
    let shortcutKey: KeyEquivalent
    let action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(isSelected ? Theme.ink : Theme.inkSecondary)
                    .frame(width: 16)
                Text(title)
                    .font(.system(size: 13, weight: isSelected ? .semibold : .regular))
                    .foregroundColor(isSelected ? Theme.ink : Theme.inkSecondary)
                Spacer()
                if badgeCount > 0 {
                    Text("\(badgeCount)")
                        .font(.system(size: 10.5, weight: .semibold).monospacedDigit())
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1.5)
                        .background(badgeColor)
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 6.5)
            .background(
                isSelected ? Theme.selection : (hovered ? Theme.selection.opacity(0.55) : Color.clear)
            )
            .cornerRadius(7)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .keyboardShortcut(shortcutKey, modifiers: .command)
        .onHover { hovered = $0 }
    }
}

private struct ActivitySidebarList: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        VStack(spacing: 0) {
            // Search + clean pill filter bar
            VStack(spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 11.5))
                        .foregroundColor(Theme.inkTertiary)
                    TextField("Search findings, paths…", text: $store.searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))
                        .foregroundColor(Theme.ink)
                    if !store.searchText.isEmpty {
                        Button { store.searchText = "" } label: {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 11.5))
                                .foregroundColor(Theme.inkTertiary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 9)
                .padding(.vertical, 6)
                .background(Theme.surface.opacity(0.75))
                .cornerRadius(7)
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.hairline, lineWidth: 1))

                HStack(spacing: 4) {
                    ForEach(ActivityFilter.allCases, id: \.self) { f in
                        let active = (store.filter == f)
                        Button {
                            store.filter = f
                        } label: {
                            Text(f.rawValue)
                                .font(.system(size: 11.5, weight: active ? .semibold : .regular))
                                .foregroundColor(active ? Theme.ink : Theme.inkSecondary)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 4)
                                .background(active ? Theme.surface : Color.clear)
                                .cornerRadius(5.5)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 5.5)
                                        .stroke(active ? Theme.hairlineStrong : Color.clear, lineWidth: 1)
                                )
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(2)
                .background(Theme.surface.opacity(0.4))
                .cornerRadius(7)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)

            let rows = store.filteredEvents
            if rows.isEmpty {
                VStack(spacing: 6) {
                    Spacer()
                    Text(store.searchText.isEmpty ? emptyCaption : "No matches")
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundColor(Theme.inkSecondary)
                    if let s = store.status, store.isAlive, store.searchText.isEmpty {
                        Text("\(s.checked) session\(s.checked == 1 ? "" : "s") checked")
                            .font(.system(size: 11.5).monospacedDigit())
                            .foregroundColor(Theme.inkTertiary)
                    }
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 3) {
                        ForEach(rows) { entry in
                            SidebarActivityRow(
                                entry: entry,
                                isSelected: store.selectedEvent?.id == entry.id,
                                answer: store.answered[entry.feedbackKey],
                                blocked: store.authError != nil
                            )
                            .onTapGesture { store.selectedEventId = entry.id }
                        }
                    }
                    .padding(.horizontal, 8)
                    .padding(.bottom, 10)
                }
            }
        }
    }

    private var emptyCaption: String {
        switch store.filter {
        case .alerts: return "No alerts"
        case .unreviewed: return "Everything triaged"
        case .all: return "Nothing flagged yet"
        }
    }
}

/// What a provider's refusal is, in the few words there is room for. Not
/// every one is a key's: an account that is not sold a model, and an AWS
/// sign-in that has run out, are refused the same way, and a new key mends
/// neither.
struct AuthProblem {
    /// Two words, for the status pill and a row's badge.
    let short: String
    /// The banner's title.
    let title: String
    /// Whether saving a key again could mend it.
    let aKeyMendsIt: Bool

    init(_ error: String) {
        let e = error.lowercased()
        if e.contains("sign-in has expired") || e.contains("sso") || e.contains("token has expired") {
            short = "Sign-in expired"
            title = "Your AWS sign-in has expired"
            aKeyMendsIt = false
        } else if e.contains("payment_instrument") || e.contains("model access is denied")
            || e.contains("insufficient_quota") || e.contains("credit balance")
        {
            short = "Model blocked"
            title = "Your account is not served this model"
            aKeyMendsIt = false
        } else {
            short = "Key rejected"
            title = "API key rejected or expired"
            aKeyMendsIt = true
        }
    }
}

private struct SidebarActivityRow: View {
    let entry: FlaggedEntry
    let isSelected: Bool
    let answer: String?
    /// Whether the models are refused: a review that waits is not under way.
    let blocked: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Circle()
                .fill(answer != nil ? Theme.inkTertiary : entry.kind.dotColor)
                .frame(width: 7, height: 7)
                .padding(.top, 5)

            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(entry.subject)
                        .font(.system(size: 12.5, weight: isSelected ? .semibold : .medium))
                        .foregroundColor(Theme.ink)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    Text(relativeTime(entry.ts))
                        .font(.system(size: 10.5).monospacedDigit())
                        .foregroundColor(Theme.inkTertiary)
                }

                Text(entry.summary)
                    .font(.system(size: 11.5))
                    .foregroundColor(Theme.inkSecondary)
                    .lineLimit(2)
                    .lineSpacing(1.5)

                if let answer {
                    let label = answers.first(where: { $0.written == answer })?.button ?? answer
                    Text(label)
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(Theme.inkTertiary)
                        .padding(.top, 1)
                } else if entry.kind == .reviewing {
                    Text(blocked ? "Not reviewed: the model is refused" : "Reviewing…")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(Theme.amber)
                        .padding(.top, 1)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? Theme.selection : Color.clear)
        )
        .contentShape(Rectangle())
    }
}

/// A count as it is read: `940`, `5.2k`, `1.3M`.
func counted(_ n: Double) -> String {
    if n < 1000 { return String(Int(n.rounded())) }
    return n < 1e6 ? String(format: "%.1fk", n / 1e3) : String(format: "%.1fM", n / 1e6)
}

/// USD as it is read: cents when there are some, else to four places.
func dollars(_ usd: Double) -> String {
    String(format: usd >= 0.1 ? "$%.2f" : "$%.4f", usd)
}

/// Seconds as they are read: `3.2s`, `48s`, `1m 25s`.
func spokenSeconds(_ seconds: Double) -> String {
    if seconds < 10 { return String(format: "%.1fs", seconds) }
    let whole = Int(seconds.rounded())
    return whole < 60 ? "\(whole)s" : "\(whole / 60)m \(whole % 60)s"
}

private struct ModelsSidebarSummary: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text("This Mac")
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(Theme.inkTertiary)

                if let s = store.status, store.isAlive {
                    Text("\(s.checked)")
                        .font(.system(size: 28, weight: .semibold).monospacedDigit())
                        .foregroundColor(Theme.ink)
                    Text("sessions checked in this run")
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkSecondary)
                } else {
                    Text("Watcher paused")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(Theme.inkSecondary)
                    Text("Zero CPU while paused")
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkTertiary)
                }
            }

            if let current = store.currentChoice {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Active pair")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(Theme.inkTertiary)
                    Text(current.name)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(Theme.ink)
                    Text(current.models)
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkSecondary)
                }
            }

            Spacer()

            VStack(alignment: .leading, spacing: 6) {
                Button { store.onOpenLog?() } label: {
                    Label("Open watch log", systemImage: "doc.text")
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkSecondary)
                }
                .buttonStyle(.plain)

                Button { store.onOpenFolder?() } label: {
                    Label("Open data folder", systemImage: "folder")
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkSecondary)
                }
                .buttonStyle(.plain)

                Button { store.onCopyStatus?() } label: {
                    Label("Copy diagnostics", systemImage: "doc.on.doc")
                        .font(.system(size: 12))
                        .foregroundColor(Theme.inkSecondary)
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(16)
    }
}

// MARK: Action Banners (only rendered when permission or key needs attention)

private struct ActionBannerStrip: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        VStack(spacing: 0) {
            if store.needsFda {
                bannerRow(
                    icon: "lock.shield.fill",
                    tint: Theme.amber,
                    title: "Full Disk Access required",
                    detail: "Grant Tangent access in System Settings to read macOS security events.",
                    buttonTitle: "Open Settings"
                ) {
                    store.onOpenFDA?()
                }
            }

            if let authErr = store.authError {
                let problem = AuthProblem(authErr)
                bannerRow(
                    icon: problem.aKeyMendsIt ? "key.slash.fill" : "exclamationmark.triangle.fill",
                    tint: Theme.amber,
                    title: problem.title,
                    detail: authErr,
                    buttonTitle: problem.aKeyMendsIt ? "Update key" : "Models"
                ) {
                    store.selectedTab = .models
                    if problem.aKeyMendsIt, let current = store.currentChoice, !current.envVars.isEmpty {
                        store.keySheetChoice = current
                    }
                }
            }

            if let err = store.lastErrorMessage {
                bannerRow(
                    icon: "exclamationmark.circle.fill",
                    tint: Theme.crimson,
                    title: "Action failed",
                    detail: err,
                    buttonTitle: "Dismiss"
                ) {
                    store.lastErrorMessage = nil
                }
            }
        }
    }

    private func bannerRow(
        icon: String,
        tint: Color,
        title: String,
        detail: String,
        buttonTitle: String,
        action: @escaping () -> Void
    ) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(Theme.ink)
                    Text(detail)
                        .font(.system(size: 11.5))
                        .foregroundColor(Theme.inkSecondary)
                        .lineLimit(2)
                }
                Spacer()
                Button(buttonTitle, action: action)
                    .buttonStyle(.borderedProminent)
                    .tint(tint)
                    .controlSize(.small)
            }
            .padding(.horizontal, 28)
            .padding(.top, 20)
            .padding(.bottom, 12)
            .background(tint.opacity(0.08))

            Rectangle().fill(Theme.hairline).frame(height: 1)
        }
    }
}

// MARK: Tab 1 Stage — Editorial Incident Brief

private struct ActivityDetailStage: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        if let entry = store.selectedEvent {
            IncidentBriefView(store: store, entry: entry)
        } else {
            QuietEmptyStage(store: store)
        }
    }
}

private struct IncidentBriefView: View {
    @ObservedObject var store: TangentStore
    let entry: FlaggedEntry
    @State private var copied = false
    /// nil: as the entry has it, open under one nobody reviewed, where the
    /// judge's note is all there is to read
    @State private var judgeNoteShown: Bool? = nil
    private var showJudgeNote: Bool { judgeNoteShown ?? (entry.kind == .unreviewed) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // Top metadata bar
                    HStack(spacing: 10) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(entry.kind.dotColor)
                                .frame(width: 7, height: 7)
                            Text(entry.kind.label)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(entry.kind == .benign ? Theme.inkSecondary : entry.kind.dotColor)
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 4)
                        .background(entry.kind.dotColor.opacity(entry.kind == .benign ? 0.10 : 0.14))
                        .clipShape(Capsule())

                        Text(formatExactTime(entry.ts))
                            .font(.system(size: 12).monospacedDigit())
                            .foregroundColor(Theme.inkTertiary)

                        Spacer()

                        Button {
                            copyReport()
                        } label: {
                            HStack(spacing: 5) {
                                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                    .font(.system(size: 11))
                                Text(copied ? "Copied" : "Copy report")
                                    .font(.system(size: 12, weight: .medium))
                            }
                            .foregroundColor(copied ? Theme.emerald : Theme.inkSecondary)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Theme.surface)
                            .cornerRadius(6)
                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Theme.hairline, lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                    }

                    // Editorial headline
                    Text(entry.subject)
                        .font(.system(size: 24, weight: .semibold))
                        .tracking(-0.4)
                        .foregroundColor(Theme.ink)
                        .textSelection(.enabled)
                        .padding(.top, 16)

                    // Executable / actor path + session id
                    HStack(spacing: 8) {
                        Text(entry.who)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(Theme.inkSecondary)
                            .textSelection(.enabled)
                            .lineLimit(2)
                        if !entry.sessionId.isEmpty {
                            Text("#\(entry.sessionId)")
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundColor(Theme.inkTertiary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Theme.surface)
                                .cornerRadius(4)
                        }
                    }
                    .padding(.top, 6)

                    Rectangle()
                        .fill(Theme.hairline)
                        .frame(height: 1)
                        .padding(.vertical, 22)

                    // Finding — clean open editorial prose with inline monospace paths
                    VStack(alignment: .leading, spacing: 8) {
                        Text(entry.kind == .unreviewed ? "Why it is unchecked"
                            : (entry.kind == .reviewing ? "First-pass summary" : "What happened"))
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundColor(Theme.inkSecondary)

                        Text(formattedBriefText(
                            entry.finding.isEmpty ? "No details recorded." : entry.finding,
                            baseSize: 14,
                            color: Theme.ink
                        ))
                        .lineSpacing(5.5)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    }

                    // What to check first — the one intentional callout container
                    if !entry.check.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 6) {
                                Image(systemName: "checklist")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(entry.kind.isAlert ? entry.kind.dotColor : Theme.inkSecondary)
                                Text("What to check first")
                                    .font(.system(size: 12.5, weight: .semibold))
                                    .foregroundColor(entry.kind.isAlert ? entry.kind.dotColor : Theme.ink)
                            }
                            Text(formattedBriefText(entry.check, baseSize: 13.5, color: Theme.ink))
                                .lineSpacing(5)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            entry.kind.isAlert
                                ? entry.kind.dotColor.opacity(0.07)
                                : Theme.surface
                        )
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(
                                    entry.kind.isAlert
                                        ? entry.kind.dotColor.opacity(0.24)
                                        : Theme.hairline,
                                    lineWidth: 1
                                )
                        )
                        .padding(.top, 22)
                    }

                    if !entry.steps.isEmpty || entry.kind == .reviewing {
                        InvestigationView(steps: entry.steps, live: entry.kind == .reviewing)
                            .padding(.top, 22)
                    }

                    // Collapsible Tier 1 Judge note
                    if !entry.judgeNote.isEmpty && entry.judgeNote != entry.finding {
                        VStack(alignment: .leading, spacing: 8) {
                            Button {
                                withAnimation(.easeOut(duration: 0.15)) {
                                    judgeNoteShown = !showJudgeNote
                                }
                            } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: showJudgeNote ? "chevron.down" : "chevron.right")
                                        .font(.system(size: 10, weight: .semibold))
                                    Text("First-pass judge note")
                                        .font(.system(size: 12, weight: .medium))
                                    if !entry.judgeMark.isEmpty {
                                        Text("(\(entry.judgeMark))")
                                            .font(.system(size: 11.5))
                                            .foregroundColor(Theme.inkTertiary)
                                    }
                                    Spacer()
                                }
                                .foregroundColor(Theme.inkSecondary)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)

                            if showJudgeNote {
                                Text(entry.judgeNote)
                                    .font(.system(size: 13))
                                    .foregroundColor(Theme.inkSecondary)
                                    .lineSpacing(4)
                                    .textSelection(.enabled)
                                    .padding(.leading, 16)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(.top, 22)
                    }
                }
                .frame(maxWidth: 640, alignment: .leading)
                .padding(.horizontal, 36)
                .padding(.top, 34)
                .padding(.bottom, 32)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            // Quiet triage bar at the bottom
            if entry.feedbackFile != nil {
                Rectangle().fill(Theme.hairline).frame(height: 1)
                HStack(spacing: 10) {
                    let current = store.answered[entry.feedbackKey]
                    if let current {
                        let label = answers.first(where: { $0.written == current })?.button ?? current
                        HStack(spacing: 6) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 12.5))
                                .foregroundColor(Theme.emerald)
                            Text("Marked as \"\(label)\"")
                                .font(.system(size: 12.5, weight: .medium))
                                .foregroundColor(Theme.inkSecondary)
                        }
                    } else {
                        Text("Was this your doing?")
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundColor(Theme.inkSecondary)
                    }

                    Spacer()

                    HStack(spacing: 8) {
                        ForEach(answers, id: \.written) { opt in
                            let chosen = (current == opt.written)
                            let isDestructive = opt.written == "not_mine" && entry.kind == .malicious
                            Button {
                                store.recordFeedback(opt.written, for: entry)
                            } label: {
                                HStack(spacing: 5) {
                                    if chosen {
                                        Image(systemName: "checkmark")
                                            .font(.system(size: 10, weight: .bold))
                                    }
                                    Text(opt.button)
                                        .font(.system(size: 12.5, weight: chosen || isDestructive ? .semibold : .medium))
                                }
                                .foregroundColor(
                                    chosen ? Theme.primaryBtnFg
                                        : (isDestructive ? Theme.crimson : Theme.ink)
                                )
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(
                                    chosen ? Theme.primaryBtnBg
                                        : (isDestructive ? Theme.crimson.opacity(0.11) : Theme.surface)
                                )
                                .cornerRadius(7)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 7)
                                        .stroke(
                                            chosen ? Color.clear
                                                : (isDestructive ? Theme.crimson.opacity(0.28) : Theme.hairlineStrong),
                                            lineWidth: 1
                                        )
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .padding(.horizontal, 28)
                .padding(.vertical, 12)
                .background(Theme.canvas)
            }
        }
    }

    private func copyReport() {
        var lines = [
            "[\(entry.kind.label)] \(entry.subject) (\(entry.ts))",
            "Path: \(entry.who)",
            "",
            "What happened: \(entry.finding)",
        ]
        if !entry.check.isEmpty {
            lines.append("")
            lines.append("What to check first: \(entry.check)")
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
    }
}

/// How a review went: each turn's reasoning, then what the reviewer asked
/// the log or read, each opening to the start of what came back. Open while
/// the review is in progress, closed under a finished one.
private struct InvestigationView: View {
    let steps: [ReviewStep]
    let live: Bool
    @State private var shown: Bool? = nil
    @State private var opened = Set<String>()

    private var asked: Int { steps.reduce(0) { $0 + $1.calls.filter { $0.tool != "report" }.count } }

    var body: some View {
        let open = shown ?? live
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.easeOut(duration: 0.15)) { shown = !open }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                    Text("Investigation")
                        .font(.system(size: 12, weight: .medium))
                    if asked > 0 {
                        Text("(\(asked) \(asked == 1 ? "lookup" : "lookups"))")
                            .font(.system(size: 11.5))
                            .foregroundColor(Theme.inkTertiary)
                    }
                    Spacer()
                }
                .foregroundColor(Theme.inkSecondary)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if open {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { i, step in
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach([step.thinking, step.said].filter { !$0.isEmpty }, id: \.self) { text in
                                Text(text)
                                    .font(.system(size: 13))
                                    .foregroundColor(Theme.inkSecondary)
                                    .lineSpacing(4)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            ForEach(Array(step.calls.enumerated()), id: \.offset) { j, call in
                                if call.tool != "report" {
                                    callRow(call, id: "\(i)-\(j)")
                                }
                            }
                        }
                    }
                    if live {
                        HStack(spacing: 7) {
                            ProgressView().controlSize(.small)
                            Text(steps.isEmpty ? "Starting…" : "Working…")
                                .font(.system(size: 12))
                                .foregroundColor(Theme.inkTertiary)
                        }
                    }
                }
                .padding(.leading, 16)
            }
        }
    }

    @ViewBuilder
    private func callRow(_ call: ReviewCall, id: String) -> some View {
        let isOpen = opened.contains(id)
        VStack(alignment: .leading, spacing: 6) {
            Button {
                if isOpen { opened.remove(id) } else { opened.insert(id) }
            } label: {
                HStack(alignment: .top, spacing: 7) {
                    Image(systemName: call.failed ? "exclamationmark.triangle"
                        : (call.tool == "read_file" ? "doc.text" : "magnifyingglass"))
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(call.failed ? Theme.crimson : Theme.inkTertiary)
                        .frame(width: 13)
                        .padding(.top, 2)
                    Text(call.asked.isEmpty ? call.tool : call.asked)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundColor(Theme.ink)
                        .lineLimit(isOpen ? nil : 2)
                        .multilineTextAlignment(.leading)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isOpen && !call.result.isEmpty {
                ScrollView(.horizontal) {
                    Text(call.result)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(Theme.inkSecondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: true, vertical: true)
                        .padding(.bottom, 6)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface)
        .cornerRadius(8)
    }
}

private struct QuietEmptyStage: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(Theme.emerald.opacity(0.10))
                    .frame(width: 56, height: 56)
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 24))
                    .foregroundColor(Theme.emerald)
            }

            Text("Everything looks quiet")
                .font(.system(size: 18, weight: .semibold))
                .tracking(-0.3)
                .foregroundColor(Theme.ink)

            Text(emptySubtitle)
                .font(.system(size: 13.5))
                .foregroundColor(Theme.inkSecondary)
                .multilineTextAlignment(.center)
                .lineSpacing(4)
                .frame(maxWidth: 360)

            Menu {
                Button("AI coding agent takeover") { store.onSimulate?("agent") }
                Button("Credentials sweep") { store.onSimulate?("credentials") }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "bolt.shield")
                        .font(.system(size: 12))
                    Text("Run a safe attack simulation")
                        .font(.system(size: 12.5, weight: .medium))
                }
                .foregroundColor(Theme.ink)
                .padding(.horizontal, 14)
                .padding(.vertical, 7)
                .background(Theme.surface)
                .cornerRadius(7)
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.hairlineStrong, lineWidth: 1))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .padding(.top, 6)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptySubtitle: String {
        if let s = store.status, store.isAlive {
            return "Tangent has checked \(s.checked) session\(s.checked == 1 ? "" : "s") with no confirmed threats. Trigger a safe simulation to see an alert land here in real time."
        }
        return "Flagged sessions and confirmed reviews appear here as Tangent watches your Mac."
    }
}

// MARK: Tab 3 Stage — Health: is it running, and how fast

/// Whether the sensor's socket is there for the watcher to read.
func sensorConnected() -> Bool {
    let dir = ProcessInfo.processInfo.environment["TANGENT_SENSOR_SOCKET_DIR"] ?? "/var/run/tangent"
    return FileManager.default.fileExists(atPath: (dir as NSString).appendingPathComponent("es.sock"))
}

private struct HealthStage: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        let s = store.status
        let alive = store.isAlive
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Health")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundColor(Theme.ink)

                group("Running") {
                    row("Watcher", alive ? "Watching" : "Paused", alive ? Theme.emerald : Theme.inkTertiary)
                    if alive, let since = s?.startedAt.flatMap(ISO8601DateFormatter.flexible) {
                        row("Since", since.formatted(date: .abbreviated, time: .shortened))
                    }
                    row("Sensor", sensorConnected() ? "Connected" : "Not connected",
                        sensorConnected() ? Theme.emerald : Theme.amber)
                    if store.needsFda {
                        row("Full Disk Access", "Needed", Theme.amber)
                    }
                    if let err = store.authError {
                        row("Models", AuthProblem(err).short, Theme.amber)
                    } else if alive {
                        row("Models", "Answering", Theme.emerald)
                    }
                }

                if alive, let s {
                    group("This run") {
                        row("Sessions checked", "\(s.checked)")
                        row("Flagged", "\(s.flagged)")
                        row("Being reviewed", "\(s.pending)")
                    }
                    group("Speed · median, 95th percentile") {
                        row("First pass", spread(s.judgeSeconds))
                        row("Flagged to verdict", spread(s.reviewSeconds))
                    }
                    if !s.usage.isEmpty {
                        let u = s.usage
                        let left = u["measuring_seconds_left"]
                        let waiting = left.map { "Measuring, ready in about \(max(1, Int(($0 / 60).rounded(.up)))) min" }
                        let none = waiting ?? "No listed price for this model"
                        group(left == nil
                            ? String(format: "Tokens and cost · from the last %.1f h measured", u["measured_hours"] ?? 0)
                            : "Tokens and cost") {
                            row("Output speed", ["judge", "reviewer"].compactMap { node in
                                u["speed.\(node)"].map { "\(node) \(Int($0.rounded())) tok/s" }
                            }.joined(separator: "  ·  "))
                            row("Tokens per activity", u["tokens_per_activity"].map(counted) ?? (waiting ?? "–"))
                            row("Cost per activity", u["cost_per_activity"].map(dollars) ?? none)
                            row("Cost per day", u["cost_per_day"].map(dollars) ?? none)
                        }
                        group("Activity") {
                            row("Per second", u["activities_per_second"].map { String(format: "%.2f", $0) } ?? (waiting ?? "–"))
                            row("Per day", u["activities_per_day"].map(counted) ?? (waiting ?? "–"))
                        }
                    }
                }

                HStack(spacing: 16) {
                    link("Open watch log", "doc.text") { store.onOpenLog?() }
                    link("Open data folder", "folder") { store.onOpenFolder?() }
                    link("Copy diagnostics", "doc.on.doc") { store.onCopyStatus?() }
                }
            }
            .frame(maxWidth: 560, alignment: .leading)
            .padding(.horizontal, 36)
            .padding(.top, 34)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func spread(_ of: (p50: Double, p95: Double)?) -> String {
        of.map { "\(spokenSeconds($0.p50))  ·  \(spokenSeconds($0.p95))" } ?? "–"
    }

    private func group<Rows: View>(_ title: String, @ViewBuilder _ rows: () -> Rows) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundColor(Theme.inkTertiary)
            VStack(spacing: 0) { rows() }
                .background(Theme.surface)
                .cornerRadius(10)
        }
    }

    private func row(_ name: String, _ value: String, _ dot: Color? = nil) -> some View {
        HStack(spacing: 8) {
            Text(name)
                .foregroundColor(Theme.inkSecondary)
            Spacer()
            if let dot {
                Circle().fill(dot).frame(width: 7, height: 7)
            }
            Text(value)
                .foregroundColor(Theme.ink)
                .monospacedDigit()
        }
        .font(.system(size: 13))
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }

    private func link(_ title: String, _ symbol: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.system(size: 12))
                .foregroundColor(Theme.inkSecondary)
        }
        .buttonStyle(.plain)
    }
}

// MARK: Tab 2 Stage — Clean Grouped Models & Keychain Settings

private struct ModelsAndKeysStage: View {
    @ObservedObject var store: TangentStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Models & Keys")
                        .font(.system(size: 22, weight: .semibold))
                        .tracking(-0.35)
                        .foregroundColor(Theme.ink)
                    Text("Choose which model pair judges this Mac. API keys live in your macOS Login Keychain and never touch plaintext files, plists, or logs.")
                        .font(.system(size: 13))
                        .foregroundColor(Theme.inkSecondary)
                        .lineSpacing(3.5)
                        .fixedSize(horizontal: false, vertical: true)
                }

                // Single clean grouped list container (Linear / Raycast settings feel)
                VStack(spacing: 0) {
                    ForEach(Array(store.choices.enumerated()), id: \.element.id) { idx, choice in
                        ProviderSettingsRow(store: store, choice: choice)
                        if idx < store.choices.count - 1 {
                            Rectangle()
                                .fill(Theme.hairline)
                                .frame(height: 1)
                                .padding(.leading, 16)
                        }
                    }
                }
                .background(Theme.surface)
                .cornerRadius(11)
                .overlay(
                    RoundedRectangle(cornerRadius: 11)
                        .stroke(Theme.hairline, lineWidth: 1)
                )

                // Quiet Keychain footnote
                HStack(alignment: .firstTextBaseline, spacing: 7) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 10.5))
                        .foregroundColor(Theme.inkTertiary)
                    Text("Stored under com.ethanblackburn.tangent in macOS Login Keychain. Only Tangent.app reads or writes keys.")
                        .font(.system(size: 11.5))
                        .foregroundColor(Theme.inkTertiary)
                        .lineSpacing(2)
                }
            }
            .frame(maxWidth: 640, alignment: .leading)
            .padding(.horizontal, 36)
            .padding(.top, 36)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct ProviderSettingsRow: View {
    @ObservedObject var store: TangentStore
    let choice: ModelChoice
    @State private var hovered = false

    /// A choice that cannot run on this Mac and has nothing to set that
    /// would let it (Inkling without the memory): shown, and greyed out.
    private var unavailable: Bool {
        !choice.current && !choice.ready && choice.envVars.isEmpty
    }

    var body: some View {
        HStack(spacing: 14) {
            // Selection indicator dot
            ZStack {
                Circle()
                    .stroke(choice.current ? Theme.emerald : Theme.hairlineStrong, lineWidth: 1.5)
                    .frame(width: 16, height: 16)
                if choice.current {
                    Circle()
                        .fill(Theme.emerald)
                        .frame(width: 8, height: 8)
                }
            }

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(choice.name)
                        .font(.system(size: 13.5, weight: .semibold))
                        .foregroundColor(Theme.ink)
                    Text(choice.models)
                        .font(.system(size: 12.5))
                        .foregroundColor(Theme.inkSecondary)
                }

                statusLine
            }

            Spacer(minLength: 12)

            HStack(spacing: 8) {
                if choice.current {
                    if !choice.envVars.isEmpty {
                        let isProfileOnly = choice.envVars.allSatisfy { !$0.secret }
                        if let err = store.authError, !AuthProblem(err).aKeyMendsIt {
                            // no key mends it: it is said, and nothing is offered
                            Text(AuthProblem(err).short)
                                .font(.system(size: 11.5, weight: .semibold))
                                .foregroundColor(Theme.amber)
                                .padding(.horizontal, 9)
                                .padding(.vertical, 4)
                                .background(Theme.amber.opacity(0.14))
                                .clipShape(Capsule())
                        } else if store.authError != nil {
                            Button("Fix key") {
                                store.keySheetChoice = choice
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(Theme.amber)
                            .controlSize(.small)
                        } else {
                            quietRowButton(isProfileOnly ? "Profile" : "Update key") {
                                store.keySheetChoice = choice
                            }
                        }
                    }
                    if store.authError == nil || choice.envVars.isEmpty {
                        Text("Active")
                            .font(.system(size: 11.5, weight: .semibold))
                            .foregroundColor(Theme.emerald)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(Theme.emerald.opacity(0.12))
                            .clipShape(Capsule())
                    }
                } else if choice.ready {
                    if !choice.envVars.isEmpty {
                        let isProfileOnly = choice.envVars.allSatisfy { !$0.secret }
                        quietRowButton(isProfileOnly ? "Profile" : "Update key") {
                            store.keySheetChoice = choice
                        }
                    }
                    quietRowButton("Use", emphasized: true) {
                        store.onRunCLI?(choice.args, "Switching…")
                    }
                } else if !choice.envVars.isEmpty {
                    quietRowButton("Add key", emphasized: true) {
                        store.keySheetChoice = choice
                    }
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .opacity(unavailable ? 0.4 : 1)
        .background(
            choice.current
                ? Theme.selection
                : (hovered && !unavailable ? Theme.selection.opacity(0.45) : Color.clear)
        )
        .onHover { hovered = $0 }
    }

    private func quietRowButton(_ title: String, emphasized: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(emphasized ? Theme.ink : Theme.inkSecondary)
                .padding(.horizontal, 11)
                .padding(.vertical, 5)
                .background(emphasized ? Theme.canvas : Color.clear)
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(emphasized ? Theme.hairlineStrong : Theme.hairline, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
        .disabled(store.busyAction != nil)
    }

    @ViewBuilder
    private var statusLine: some View {
        if choice.provider == "local" {
            if choice.ready {
                Text("Runs locally via Ollama — nothing leaves your Mac")
                    .font(.system(size: 11.5))
                    .foregroundColor(Theme.inkTertiary)
            } else {
                Text(choice.note ?? "Requires Apple Silicon with 32 GB memory")
                    .font(.system(size: 11.5))
                    .foregroundColor(Theme.inkTertiary)
            }
        } else if choice.provider == "bedrock" {
            let profile = choice.envVars.first?.value ?? "default"
            Text("AWS profile \(profile) via ~/.aws")
                .font(.system(size: 11.5))
                .foregroundColor(Theme.inkTertiary)
        } else if let envVar = choice.envVars.first {
            if envVar.isSet {
                HStack(spacing: 5) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 10.5))
                        .foregroundColor(Theme.emerald)
                    Text("\(envVar.name) saved in Keychain")
                        .font(.system(size: 11.5))
                        .foregroundColor(Theme.inkSecondary)
                }
            } else {
                Text("\(envVar.name) not set")
                    .font(.system(size: 11.5))
                    .foregroundColor(Theme.inkTertiary)
            }
        }
    }
}

// MARK: Key / Profile Editor Sheet

private struct KeyEditorSheet: View {
    @ObservedObject var store: TangentStore
    let choice: ModelChoice
    @State private var draftValues: [String: String] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(choice.provider == "bedrock" ? "Bedrock profile" : "\(choice.name) API key")
                    .font(.system(size: 17, weight: .semibold))
                    .tracking(-0.2)
                    .foregroundColor(Theme.ink)
                Text(choice.models)
                    .font(.system(size: 12.5))
                    .foregroundColor(Theme.inkSecondary)
            }

            ForEach(choice.envVars) { envVar in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(envVar.name)
                            .font(.system(size: 12, weight: .medium, design: .monospaced))
                            .foregroundColor(Theme.ink)
                        Spacer()
                        if envVar.isSet && envVar.secret {
                            Text("Saved in Keychain")
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundColor(Theme.emerald)
                        }
                    }

                    Group {
                        if envVar.secret {
                            SecureField(
                                envVar.isSet ? "Paste a new key to replace existing…" : "Paste \(envVar.name)…",
                                text: binding(for: envVar.name)
                            )
                        } else {
                            TextField(
                                envVar.value ?? "default",
                                text: binding(for: envVar.name)
                            )
                        }
                    }
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, design: .monospaced))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .background(Theme.surface)
                    .cornerRadius(7)
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(Theme.hairlineStrong, lineWidth: 1))

                    if !envVar.description.isEmpty {
                        Text(envVar.description)
                            .font(.system(size: 11.5))
                            .foregroundColor(Theme.inkTertiary)
                    }
                }
            }

            Text(
                choice.provider == "bedrock"
                    ? "If your AWS SSO session expires, run `aws sso login` in a terminal — Tangent picks up the refreshed token automatically."
                    : "Stored securely in your macOS Login Keychain. Tangent restarts with the new key immediately."
            )
            .font(.system(size: 11.5))
            .foregroundColor(Theme.inkSecondary)
            .lineSpacing(2.5)

            Rectangle().fill(Theme.hairline).frame(height: 1)

            HStack(spacing: 10) {
                if choice.envVars.contains(where: { $0.isSet }) {
                    Button("Remove saved key") {
                        store.clearKeys(for: choice)
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(Theme.crimson)
                }

                Spacer()

                Button("Cancel") {
                    store.keySheetChoice = nil
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.bordered)

                Button {
                    store.saveKeyAndActivate(choice: choice, values: draftValues, activate: true)
                } label: {
                    Text(choice.current ? "Save & restart" : "Save & use \(choice.name)")
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(Theme.primaryBtnFg)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(canSave ? Theme.primaryBtnBg : Theme.primaryBtnBg.opacity(0.35))
                        .cornerRadius(7)
                }
                .buttonStyle(.plain)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Theme.canvas)
        .onAppear {
            for v in choice.envVars {
                if !v.secret, let val = v.value {
                    draftValues[v.name] = val
                }
            }
        }
    }

    private func binding(for name: String) -> Binding<String> {
        Binding(
            get: { draftValues[name] ?? "" },
            set: { draftValues[name] = $0 }
        )
    }

    private var canSave: Bool {
        var enteredAnySecret = false
        var changedNonSecret = false
        for v in choice.envVars {
            let entered = (draftValues[v.name] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if v.required && entered.isEmpty && !v.isSet { return false }
            if v.secret && !entered.isEmpty { enteredAnySecret = true }
            if !v.secret && entered != (v.value ?? "") { changedNonSecret = true }
        }
        if choice.current {
            return enteredAnySecret || changedNonSecret
        }
        return true
    }
}

// MARK: AppKit Window Controller + Standard Edit Menu (so Cmd+V works!)

final class TangentWindowController: NSWindowController {
    let store: TangentStore

    init(store: TangentStore) {
        self.store = store
        let rootView = TangentAppView(store: store)
        let host = NSHostingController(rootView: rootView)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 600),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Tangent"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.contentViewController = host
        window.minSize = NSSize(width: 820, height: 540)
        window.isReleasedWhenClosed = false
        window.center()
        super.init(window: window)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    func show() {
        store.reloadHistory()
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
    }
}

/// Installs a minimal standard macOS Edit + Window menu on `NSApp.mainMenu`
/// so Cmd+C, Cmd+V, Cmd+X, Cmd+A, Cmd+Z, and Cmd+W work inside text and
/// password fields even though Tangent runs as an accessory (LSUIElement) app.
func installStandardMainMenu() {
    let main = NSMenu()

    let appItem = NSMenuItem()
    let appMenu = NSMenu()
    appMenu.addItem(withTitle: "Hide Tangent", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
    appMenu.addItem(.separator())
    appMenu.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
    appItem.submenu = appMenu
    main.addItem(appItem)

    let editItem = NSMenuItem()
    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
    editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
    editMenu.addItem(.separator())
    editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    editItem.submenu = editMenu
    main.addItem(editItem)

    NSApp.mainMenu = main
}
