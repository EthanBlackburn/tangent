// menubar.swift: native macOS menu bar app for Tangent (`Tangent.app`).
//
//   tangent-sensor menubar [--dir ~/.local/share/tangent/mac] [--tangent /path/to/tangent]
//
// Runs unprivileged in the user's Aqua GUI session (`LSUIElement = true`,
// zero Dock icon). Watches `status.json` and `feedback.ndjson` via kqueue,
// with a look every five seconds for a watcher that ended without saying so
// and for the alerts' ages, renders a crisp monochrome template icon with an optional
// status dot only when action is needed, and opens a native Alert Inspector
// panel for any recent alert or clicked notification.

import AppKit
import Foundation
import UserNotifications

// MARK: data model (matches crates/cli/src/status.rs)

struct AlertItem {
    let ts: String
    let verdict: String
    let subject: String
    let who: String
    let summary: String
    let finding: String
    let check: String
    let feedbackFile: String?
    let feedbackLine: [String: Any]?

    /// Stable key matching `feedback.ndjson` lines (`session.id` + `reviewed` ts).
    var feedbackKey: String {
        let sid = (feedbackLine?["session"] as? [String: Any])?["id"] as? String ?? ""
        return "\(sid)|\(ts)"
    }

    static func parse(_ dict: [String: Any]) -> AlertItem? {
        let s = { (k: String) in dict[k] as? String ?? "" }
        let verdict = s("verdict")
        guard !verdict.isEmpty else { return nil }
        return AlertItem(
            ts: s("ts"),
            verdict: verdict,
            subject: s("subject"),
            who: s("who"),
            summary: s("summary"),
            finding: s("finding"),
            check: s("check"),
            feedbackFile: dict["feedback_file"] as? String,
            feedbackLine: dict["feedback_line"] as? [String: Any]
        )
    }
}

/// A session the watcher has in hand and has not judged: still being
/// gathered, or with the judge.
struct UnderwaySession: Identifiable, Equatable {
    let id: String
    /// `grouping` or `judging`.
    let stage: String
    let entry: String
    let events: Int
    let since: String

    static func parse(_ of: [String: Any]) -> UnderwaySession? {
        guard let stage = of["stage"] as? String else { return nil }
        let sid = of["id"] as? String ?? ""
        let window = of["window"] as? String ?? ""
        return UnderwaySession(
            id: "\(stage)|\(sid)|\(window)",
            stage: stage,
            entry: of["entry"] as? String ?? "",
            events: of["events"] as? Int ?? 0,
            since: of["since"] as? String ?? ""
        )
    }
}

struct WatchStatus {
    let state: String
    let pid: Int32?
    let startedAt: String?
    let updatedAt: String
    let mode: String
    let models: String
    let checked: Int
    let flagged: Int
    let pending: Int
    let alerts: Int
    let recentAlerts: [AlertItem]
    let error: String?
    let needsFda: Bool
    let authError: String?
    /// How long the models take in this run, in seconds, the median and
    /// the 95th percentile: the judge a request, and an alert from flagged
    /// to its review's verdict. Nil until there is one.
    let judgeSeconds: (p50: Double, p95: Double)?
    let reviewSeconds: (p50: Double, p95: Double)?
    /// This run's tokens, cost and rate, as the watcher works them out:
    /// numbers by name, a node's output speed under `speed.<node>`.
    let usage: [String: Double]
    /// Sessions not yet judged: how many are being gathered and how many
    /// are with the judge, and the latest of them.
    let grouping: Int
    let judging: Int
    let underway: [UnderwaySession]

    /// True if the watch process is actually alive right now.
    var isAlive: Bool {
        guard state == "watching" || state == "starting", let pid, pid > 0 else { return false }
        return Darwin.kill(pid, 0) == 0 || errno == EPERM
    }

    private static func spread(_ value: Any?) -> (p50: Double, p95: Double)? {
        guard let of = value as? [String: Any],
              let p50 = (of["p50"] as? NSNumber)?.doubleValue,
              let p95 = (of["p95"] as? NSNumber)?.doubleValue else { return nil }
        return (p50, p95)
    }

    static func load(from dir: String) -> WatchStatus? {
        let path = (dir as NSString).appendingPathComponent("status.json")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        let s = { (k: String) in dict[k] as? String ?? "" }
        let n = { (k: String) in dict[k] as? Int ?? 0 }
        let recent = (dict["recent_alerts"] as? [[String: Any]] ?? []).compactMap(AlertItem.parse)
        let pidVal = (dict["pid"] as? Int).map { Int32($0) }
        return WatchStatus(
            state: s("state"),
            pid: pidVal,
            startedAt: dict["started_at"] as? String,
            updatedAt: s("updated_at"),
            mode: s("mode"),
            models: s("models"),
            checked: n("checked"),
            flagged: n("flagged"),
            pending: n("pending"),
            alerts: n("alerts"),
            recentAlerts: recent,
            error: dict["error"] as? String,
            needsFda: dict["needs_fda"] as? Bool ?? false,
            authError: dict["auth_error"] as? String,
            judgeSeconds: spread(dict["judge_seconds"]),
            reviewSeconds: spread(dict["review_seconds"]),
            usage: {
                var flat: [String: Double] = [:]
                for (key, value) in dict["usage"] as? [String: Any] ?? [:] {
                    if let n = value as? NSNumber, !(value is Bool) { flat[key] = n.doubleValue }
                    for (node, speed) in value as? [String: Any] ?? [:] {
                        if let n = speed as? NSNumber { flat["speed.\(node)"] = n.doubleValue }
                    }
                }
                return flat
            }(),
            grouping: (dict["underway"] as? [String: Any])?["grouping"] as? Int ?? 0,
            judging: (dict["underway"] as? [String: Any])?["judging"] as? Int ?? 0,
            underway: ((dict["underway"] as? [String: Any])?["sessions"] as? [[String: Any]] ?? [])
                .compactMap(UnderwaySession.parse)
        )
    }
}

/// One way to judge this Mac, from `tangent status --json`'s `choices`: the
/// model on this Mac, or a provider's pair.
struct ModelChoice: Identifiable {
    var id: String { provider.isEmpty ? name : provider }
    let provider: String
    /// Who serves the models, and the models, each in a few words.
    let name: String
    let models: String
    /// What `tangent` is run with to start it.
    let args: [String]
    let current: Bool
    /// Whether it can be started from here, where there is nobody to ask.
    let ready: Bool
    /// When it cannot, why.
    let note: String?
    /// Configurable environment variables (API keys / AWS profile).
    let envVars: [ProviderEnvVar]

    static func parse(_ dict: [String: Any]) -> ModelChoice? {
        guard let name = dict["name"] as? String, let args = dict["args"] as? [String], !args.isEmpty
        else { return nil }
        let envVars = (dict["env_vars"] as? [[String: Any]] ?? []).compactMap(ProviderEnvVar.parse)
        return ModelChoice(
            provider: dict["provider"] as? String ?? name.lowercased(),
            name: name,
            models: dict["models"] as? String ?? "",
            args: args,
            current: dict["current"] as? Bool ?? false,
            ready: dict["ready"] as? Bool ?? false,
            note: dict["note"] as? String,
            envVars: envVars
        )
    }
}

/// Reads answered alert keys (`session.id|reviewed`) from `feedback.ndjson`.
private func loadAnsweredAlerts(in dir: String) -> [String: String] {
    let path = (dir as NSString).appendingPathComponent("feedback.ndjson")
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [:] }
    var answered: [String: String] = [:]
    for line in text.split(separator: "\n") {
        guard let data = line.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let answer = obj["answer"] as? String
        else { continue }
        let sid = (obj["session"] as? [String: Any])?["id"] as? String ?? ""
        let reviewed = obj["reviewed"] as? String ?? ""
        answered["\(sid)|\(reviewed)"] = answer
    }
    return answered
}

// MARK: vector template icon (drawn from icon.svg)

/// Crisp 18x18 monochrome template icon matching Tangent's stacked chevron mark.
/// Because `isTemplate = true`, macOS automatically adapts it to light, dark,
/// and translucent wallpaper menu bars.
private func makeTangentTemplateIcon() -> NSImage {
    let size = NSSize(width: 18, height: 18)
    let image = NSImage(size: size, flipped: true) { rect in
        NSColor.black.setFill()
        // Coordinates normalized from icon.svg (viewBox 1024x1024, centered mark).
        // Top solid chevron layer + bottom offset chevron layer, scaled cleanly
        // into the 18x18 menu bar optical box.
        let top = NSBezierPath()
        top.move(to: NSPoint(x: 2.4, y: 10.7))
        top.line(to: NSPoint(x: 8.9, y: 5.7))
        top.line(to: NSPoint(x: 6.1, y: 3.5))
        top.line(to: NSPoint(x: 7.6, y: 2.3))
        top.line(to: NSPoint(x: 16.0, y: 8.8))
        top.line(to: NSPoint(x: 14.5, y: 10.0))
        top.line(to: NSPoint(x: 11.4, y: 7.6))
        top.line(to: NSPoint(x: 4.8, y: 12.7))
        top.close()
        top.lineJoinStyle = .round
        top.fill()

        // Lower parallel ribbon giving the signature stacked Tangent silhouette.
        let bottom = NSBezierPath()
        bottom.move(to: NSPoint(x: 2.4, y: 13.7))
        bottom.line(to: NSPoint(x: 5.0, y: 15.7))
        bottom.line(to: NSPoint(x: 11.4, y: 10.8))
        bottom.line(to: NSPoint(x: 14.5, y: 13.2))
        bottom.line(to: NSPoint(x: 16.0, y: 12.0))
        bottom.line(to: NSPoint(x: 11.4, y: 8.5))
        bottom.line(to: NSPoint(x: 4.8, y: 13.6))
        bottom.line(to: NSPoint(x: 3.6, y: 12.7))
        bottom.close()
        bottom.lineJoinStyle = .round
        bottom.fill()
        return true
    }
    image.isTemplate = true
    return image
}

private func symbolImage(_ name: String, color: NSColor) -> NSImage? {
    let config = NSImage.SymbolConfiguration(pointSize: 12, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
    return NSImage(systemSymbolName: name, accessibilityDescription: nil)?
        .withSymbolConfiguration(config)
}

func relativeTime(_ rfc3339: String) -> String {
    let fmt = ISO8601DateFormatter()
    fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = fmt.date(from: rfc3339) ?? ISO8601DateFormatter().date(from: rfc3339)
    guard let date else { return rfc3339 }
    let secs = max(0, Int(Date().timeIntervalSince(date)))
    if secs < 60 { return "just now" }
    if secs < 3600 { return "\(secs / 60)m ago" }
    if secs < 86400 { return "\(secs / 3600)h ago" }
    return "\(secs / 86400)d ago"
}

// MARK: menu bar controller

private let openWindowNotification = Notification.Name("com.ethanblackburn.tangent.openWindow")

private final class MenuBarController: NSObject, NSApplicationDelegate, NSMenuDelegate, UNUserNotificationCenterDelegate {
    let watchDir: String
    let tangentBin: String
    let store: TangentStore

    private var statusItem: NSStatusItem!
    private var dotLayer: CALayer?
    private var dirSource: DispatchSourceFileSystemObject?
    private var dirFd: Int32 = -1
    private var timer: Timer?
    private var currentStatus: WatchStatus?
    private var answered: [String: String] = [:]
    private var windowController: TangentWindowController?
    private var busyAction: String?
    /// Who can judge this Mac, as `tangent status --json` last listed them.
    private var modelChoices: [ModelChoice] = []

    init(watchDir: String, tangentBin: String) {
        self.watchDir = watchDir
        self.tangentBin = tangentBin
        self.store = TangentStore(watchDir: watchDir, tangentBin: tangentBin)
        super.init()
        wireStore()
    }

    private func wireStore() {
        store.onRunCLI = { [weak self] args, label in
            self?.runTangentCLI(args, busyLabel: label)
        }
        store.onSimulate = { [weak self] name in
            self?.launchSimulation(name)
        }
        store.onOpenFDA = { [weak self] in
            self?.openFullDiskAccess()
        }
        store.onOpenLog = { [weak self] in
            self?.openWatchLog()
        }
        store.onOpenFolder = { [weak self] in
            self?.openDataFolder()
        }
        store.onCopyStatus = { [weak self] in
            self?.copyDiagnostics()
        }
        store.onReloadRequested = { [weak self] in
            self?.reload()
            self?.refreshModelChoices()
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStandardMainMenu()

        // Set notification delegate so clicks on banners route directly here.
        if Bundle.main.bundleIdentifier != nil {
            let center = UNUserNotificationCenter.current()
            center.delegate = self
            registerAnswers(center)
        }

        // Bring the main window forward if the user opens Tangent.app again
        // from Finder / Spotlight while this menu bar instance is running.
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(openMainWindow),
            name: openWindowNotification,
            object: nil
        )

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = makeTangentTemplateIcon()
            button.imagePosition = .imageOnly
            button.wantsLayer = true
            button.toolTip = "Tangent"
        }

        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        startWatchingDirectory()
        reload()
        refreshModelChoices()

        // Lightweight liveness + relative-time refresh (5s).
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.reload()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        DistributedNotificationCenter.default().removeObserver(self)
        timer?.invalidate()
        dirSource?.cancel()
        if dirFd >= 0 { Darwin.close(dirFd) }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openMainWindow()
        return true
    }

    @objc func openMainWindow() {
        let controller = ensureWindowController()
        controller.show()
    }

    private func ensureWindowController() -> TangentWindowController {
        if let existing = windowController {
            return existing
        }
        let created = TangentWindowController(store: store)
        windowController = created
        return created
    }

    // MARK: notification click handling inside the menu bar app

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let content = response.notification.request.content
        let action = response.actionIdentifier
        if action == UNNotificationDefaultActionIdentifier {
            DispatchQueue.main.async { [weak self] in
                self?.openNotificationDetail(content)
            }
        } else if answers.contains(where: { $0.written == action }) {
            keep(action, for: content.userInfo)
            DispatchQueue.main.async { [weak self] in self?.reload() }
        }
        completionHandler()
    }

    private func openNotificationDetail(_ content: UNNotificationContent) {
        reload()
        let matched = currentStatus?.recentAlerts.first(where: {
            $0.who == content.subtitle || $0.subject == content.subtitle
        })
        store.selectAlert(
            matchingSubjectOrTs: matched?.ts ?? "",
            subject: matched?.subject ?? content.subtitle
        )
        openMainWindow()
    }

    // MARK: kqueue directory watcher

    private func startWatchingDirectory() {
        try? FileManager.default.createDirectory(atPath: watchDir, withIntermediateDirectories: true)
        dirFd = Darwin.open(watchDir, O_EVTONLY)
        guard dirFd >= 0 else { return }
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: dirFd,
            eventMask: [.write, .rename, .extend, .attrib],
            queue: .main
        )
        src.setEventHandler { [weak self] in
            self?.reload()
        }
        dirSource = src
        src.resume()
    }

    // MARK: state & icon refresh

    private func reload() {
        currentStatus = WatchStatus.load(from: watchDir)
        answered = loadAnsweredAlerts(in: watchDir)
        store.status = currentStatus
        store.answered = answered
        if windowController?.window?.isVisible == true {
            store.reloadHistory()
        }
        updateIcon()
    }

    private var unacknowledgedAlerts: [AlertItem] {
        (currentStatus?.recentAlerts ?? []).filter { answered[$0.feedbackKey] == nil }
    }

    private var daemonConnected: Bool {
        let sockDir = ProcessInfo.processInfo.environment["TANGENT_SENSOR_SOCKET_DIR"] ?? "/var/run/tangent"
        let esPath = (sockDir as NSString).appendingPathComponent("es.sock")
        return FileManager.default.fileExists(atPath: esPath)
    }

    private var activeAuthError: String? {
        guard currentStatus?.isAlive == true,
              let err = currentStatus?.authError, !err.isEmpty
        else { return nil }
        return err
    }

    private func updateIcon() {
        guard let button = statusItem.button else { return }
        let status = currentStatus
        let alive = status?.isAlive ?? false
        let needsFda = status?.needsFda ?? false
        let hasAuthErr = activeAuthError != nil
        let hasError = (status?.state == "error") && !alive
        let unread = unacknowledgedAlerts

        button.appearsDisabled = !alive && unread.isEmpty && !needsFda && !hasError && !hasAuthErr

        let dotColor: NSColor?
        if !unread.isEmpty {
            dotColor = .systemRed
            button.toolTip = "Tangent — \(unread.count) alert\(unread.count == 1 ? "" : "s") to review"
        } else if needsFda || hasAuthErr || hasError {
            dotColor = .systemOrange
            if needsFda {
                button.toolTip = "Tangent — Grant Full Disk Access"
            } else if hasAuthErr {
                button.toolTip = "Tangent — \(AuthProblem(activeAuthError ?? "").short)"
            } else {
                button.toolTip = "Tangent — Attention needed"
            }
        } else if alive {
            dotColor = nil
            let count = status?.checked ?? 0
            button.toolTip = "Tangent — Watching this Mac (\(count) checked)"
        } else {
            dotColor = nil
            button.toolTip = "Tangent — Paused"
        }

        dotLayer?.removeFromSuperlayer()
        dotLayer = nil
        if let color = dotColor, let hostLayer = button.layer {
            let dot = CALayer()
            let diameter: CGFloat = 6.0
            dot.frame = CGRect(
                x: button.bounds.width - diameter - 2.5,
                y: 3.0,
                width: diameter,
                height: diameter
            )
            dot.cornerRadius = diameter / 2.0
            dot.backgroundColor = color.cgColor
            hostLayer.addSublayer(dot)
            dotLayer = dot
        }
    }

    // MARK: NSMenuDelegate (rebuild cleanly on open)

    func menuNeedsUpdate(_ menu: NSMenu) {
        reload()
        menu.removeAllItems()

        let status = currentStatus
        let alive = status?.isAlive ?? false
        let needsFda = status?.needsFda ?? false
        let authErr = activeAuthError
        let hasError = (status?.state == "error") && !alive
        let unread = unacknowledgedAlerts

        // 0. Open companion window
        let openApp = NSMenuItem(title: "Open Tangent…", action: #selector(openMainWindow), keyEquivalent: "o")
        openApp.target = self
        menu.addItem(openApp)
        menu.addItem(.separator())

        // 1. Status header
        let headerTitle: String
        let headerSymbol: String
        let headerColor: NSColor
        if let busyAction {
            headerTitle = busyAction
            headerSymbol = "ellipsis.circle.fill"
            headerColor = .secondaryLabelColor
        } else if needsFda {
            headerTitle = "Needs Full Disk Access"
            headerSymbol = "exclamationmark.triangle.fill"
            headerColor = .systemOrange
        } else if let authErr {
            let problem = AuthProblem(authErr)
            headerTitle = problem.title
            headerSymbol = problem.aKeyMendsIt ? "key.slash.fill" : "exclamationmark.triangle.fill"
            headerColor = .systemOrange
        } else if hasError {
            headerTitle = "Watcher Stopped (Error)"
            headerSymbol = "exclamationmark.circle.fill"
            headerColor = .systemOrange
        } else if alive && status?.state == "starting" {
            headerTitle = "Starting…"
            headerSymbol = "circle.fill"
            headerColor = .systemYellow
        } else if alive {
            headerTitle = "Watching this Mac"
            headerSymbol = "circle.fill"
            headerColor = .systemGreen
        } else {
            headerTitle = "Paused"
            headerSymbol = "pause.circle.fill"
            headerColor = .secondaryLabelColor
        }

        let header = NSMenuItem(title: headerTitle, action: nil, keyEquivalent: "")
        header.image = symbolImage(headerSymbol, color: headerColor)
        header.isEnabled = false
        menu.addItem(header)

        // 2. Model + activity subtitles
        if let models = status?.models, !models.isEmpty {
            let modelItem = NSMenuItem(title: "  \(models)", action: nil, keyEquivalent: "")
            modelItem.isEnabled = false
            menu.addItem(modelItem)
        }

        // Who judges: the model on this Mac, or a provider's pair. Providers
        // without a saved key open the key sheet instead of staying greyed out.
        if !modelChoices.isEmpty {
            let pickItem = NSMenuItem(title: "Models", action: nil, keyEquivalent: "")
            let pickMenu = NSMenu()
            pickMenu.autoenablesItems = false
            for (index, choice) in modelChoices.enumerated() {
                let canConfigureKey = !choice.envVars.isEmpty
                let suffix = (!choice.ready && canConfigureKey) ? " (Set key…)" : ""
                let item = NSMenuItem(
                    title: "\(choice.name)  ·  \(choice.models)\(suffix)",
                    action: #selector(chooseModels(_:)), keyEquivalent: "")
                item.target = self
                item.tag = index
                item.state = choice.current ? .on : .off
                item.isEnabled = (choice.ready || canConfigureKey) && busyAction == nil
                item.toolTip = choice.note
                pickMenu.addItem(item)
            }
            pickMenu.addItem(.separator())
            let manageKeys = NSMenuItem(title: "Manage API Keys…", action: #selector(openModelsTab), keyEquivalent: "")
            manageKeys.target = self
            pickMenu.addItem(manageKeys)
            pickItem.submenu = pickMenu
            menu.addItem(pickItem)
        }

        if alive, let status {
            let noun = status.checked == 1 ? "session" : "sessions"
            var stats = "  \(status.checked) \(noun) checked"
            if status.pending > 0 {
                stats += " · \(status.pending) reviewing…"
            } else if unread.isEmpty {
                stats += " · all clear"
            } else {
                stats += " · \(unread.count) alert\(unread.count == 1 ? "" : "s")"
            }
            let statsItem = NSMenuItem(title: stats, action: nil, keyEquivalent: "")
            statsItem.isEnabled = false
            menu.addItem(statsItem)
        } else if let err = status?.error, !err.isEmpty, !needsFda {
            let shortErr = err.count > 68 ? String(err.prefix(65)) + "…" : err
            let errItem = NSMenuItem(title: "  \(shortErr)", action: nil, keyEquivalent: "")
            errItem.isEnabled = false
            menu.addItem(errItem)
        }

        // 3. One-click fixes when action is needed
        if needsFda {
            menu.addItem(.separator())
            let fda = NSMenuItem(title: "Grant Full Disk Access…", action: #selector(openFullDiskAccess), keyEquivalent: "")
            fda.target = self
            fda.image = symbolImage("lock.shield", color: .systemOrange)
            menu.addItem(fda)
        }

        if let authErr {
            menu.addItem(.separator())
            // a key is offered only for what a key mends; the rest opens the
            // window, where the provider's own words are
            let aKeyMendsIt = AuthProblem(authErr).aKeyMendsIt
            let fixKey = NSMenuItem(
                title: aKeyMendsIt ? "Update API Key…" : "See Why…",
                action: aKeyMendsIt ? #selector(openUpdateActiveKey) : #selector(openMainWindow),
                keyEquivalent: "")
            fixKey.target = self
            fixKey.image = symbolImage(aKeyMendsIt ? "key.fill" : "exclamationmark.triangle.fill", color: .systemOrange)
            fixKey.toolTip = authErr
            menu.addItem(fixKey)
        }

        // 4. Recent Alerts section
        menu.addItem(.separator())
        let alerts = status?.recentAlerts ?? []
        if alerts.isEmpty {
            let none = NSMenuItem(title: "No recent alerts", action: nil, keyEquivalent: "")
            none.isEnabled = false
            menu.addItem(none)
        } else {
            let heading = NSMenuItem(title: "Recent Alerts", action: nil, keyEquivalent: "")
            heading.isEnabled = false
            menu.addItem(heading)
            for (index, alert) in alerts.enumerated() {
                let isAnswered = answered[alert.feedbackKey] != nil
                let label = alert.subject.isEmpty ? alert.who : alert.subject
                let title = "\(label) · \(relativeTime(alert.ts))"
                let item = NSMenuItem(title: title, action: #selector(openAlert(_:)), keyEquivalent: "")
                item.target = self
                item.tag = index
                if isAnswered {
                    item.image = symbolImage("checkmark.circle", color: .secondaryLabelColor)
                } else {
                    let color: NSColor = alert.verdict == "malicious" ? .systemRed : .systemOrange
                    item.image = symbolImage("exclamationmark.circle.fill", color: color)
                }
                item.toolTip = alert.summary
                menu.addItem(item)
            }
        }

        // 5. Primary controls
        menu.addItem(.separator())
        if alive {
            let pause = NSMenuItem(title: "Pause Watching", action: #selector(pauseWatching), keyEquivalent: "")
            pause.target = self
            pause.isEnabled = (busyAction == nil)
            menu.addItem(pause)
        } else {
            let resume = NSMenuItem(title: "Resume Watching", action: #selector(resumeWatching), keyEquivalent: "")
            resume.target = self
            resume.isEnabled = (busyAction == nil)
            menu.addItem(resume)
        }

        // Attack simulation submenu
        let simItem = NSMenuItem(title: "Run Attack Simulation", action: nil, keyEquivalent: "")
        let simMenu = NSMenu()
        let simAgent = NSMenuItem(title: "AI coding agent takeover", action: #selector(simulateAgent), keyEquivalent: "")
        simAgent.target = self
        simMenu.addItem(simAgent)
        let simCreds = NSMenuItem(title: "Credentials sweep", action: #selector(simulateCredentials), keyEquivalent: "")
        simCreds.target = self
        simMenu.addItem(simCreds)
        simItem.submenu = simMenu
        menu.addItem(simItem)

        // 6. Utilities
        menu.addItem(.separator())
        let openLog = NSMenuItem(title: "Open Watch Log", action: #selector(openWatchLog), keyEquivalent: "")
        openLog.target = self
        menu.addItem(openLog)

        let openDir = NSMenuItem(title: "Open Data Folder", action: #selector(openDataFolder), keyEquivalent: "")
        openDir.target = self
        menu.addItem(openDir)

        let copyDiag = NSMenuItem(title: "Copy Status", action: #selector(copyDiagnostics), keyEquivalent: "")
        copyDiag.target = self
        menu.addItem(copyDiag)

        // 7. Quit
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit Tangent", action: #selector(quitTangent), keyEquivalent: "q")
        quit.toolTip = "Stops watching and removes this icon. `tangent up` starts both again."
        quit.target = self
        menu.addItem(quit)
    }

    // MARK: actions

    @objc private func openAlert(_ sender: NSMenuItem) {
        guard let alerts = currentStatus?.recentAlerts, sender.tag >= 0, sender.tag < alerts.count else { return }
        let alert = alerts[sender.tag]
        store.selectAlert(matchingSubjectOrTs: alert.ts, subject: alert.subject)
        openMainWindow()
    }

    @objc private func openModelsTab() {
        store.selectedTab = .models
        openMainWindow()
    }

    @objc private func openUpdateActiveKey() {
        store.selectedTab = .models
        if let active = modelChoices.first(where: { $0.current }), !active.envVars.isEmpty {
            store.keySheetChoice = active
        }
        openMainWindow()
    }

    @objc private func openFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc private func pauseWatching() {
        runTangentCLI(["down"], busyLabel: "Pausing…")
    }

    @objc private func resumeWatching() {
        runTangentCLI(["up"], busyLabel: "Starting…")
    }

    private func runTangentCLI(_ args: [String], busyLabel: String) {
        busyAction = busyLabel
        store.busyAction = busyLabel
        updateIcon()
        let bin = tangentBin
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: bin)
            proc.arguments = args
            let said = Pipe()
            proc.standardInput = FileHandle.nullDevice
            proc.standardOutput = FileHandle.nullDevice
            proc.standardError = said
            // A Process that was never started must not be waited for: that
            // is an exception, and the end of the menu bar.
            var failure: String?
            do {
                try proc.run()
                // read to its end before the wait, so a long error fills no pipe
                let err = String(decoding: said.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                proc.waitUntilExit()
                if proc.terminationStatus != 0 {
                    let why = err.trimmingCharacters(in: .whitespacesAndNewlines)
                    failure = why.isEmpty
                        ? "`tangent \(args.joined(separator: " "))` did not finish (exit \(proc.terminationStatus))."
                        : String(why.suffix(700))
                }
            } catch {
                failure = "\(bin) could not be started: \(error.localizedDescription)"
            }
            DispatchQueue.main.async {
                self?.busyAction = nil
                self?.store.busyAction = nil
                self?.reload()
                self?.refreshModelChoices()
                if let failure { self?.sayFailed(failure, args: args) }
            }
        }
    }

    @objc private func chooseModels(_ sender: NSMenuItem) {
        guard sender.tag >= 0, sender.tag < modelChoices.count else { return }
        let choice = modelChoices[sender.tag]
        if !choice.ready {
            guard !choice.envVars.isEmpty else { return }
            store.selectedTab = .models
            store.keySheetChoice = choice
            openMainWindow()
            return
        }
        guard !choice.current else { return }
        runTangentCLI(choice.args, busyLabel: "Switching models…")
    }

    /// Asks tangent who can judge this Mac, off the main thread: which is in
    /// use, and which have what they need. It is asked at the start and after
    /// each command run from here, not each time the menu opens.
    private func refreshModelChoices() {
        let bin = tangentBin
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: bin)
            proc.arguments = ["status", "--json"]
            let out = Pipe()
            proc.standardInput = FileHandle.nullDevice
            proc.standardOutput = out
            proc.standardError = FileHandle.nullDevice
            guard (try? proc.run()) != nil else { return }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            guard let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let listed = dict["choices"] as? [[String: Any]]
            else { return }
            let choices = listed.compactMap(ModelChoice.parse)
            DispatchQueue.main.async {
                self?.modelChoices = choices
                self?.store.choices = choices
            }
        }
    }

    /// `tangent up` asks for a password the first time, and for the model
    /// when it is not on this Mac, and from here there is nobody to ask: the
    /// way on is the same command in a terminal.
    private func sayFailed(_ what: String, args: [String]) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Tangent could not do that"
        alert.informativeText = "\(what)\n\nRun `tangent \(args.joined(separator: " "))` in a terminal to see why."
        alert.runModal()
    }

    @objc private func simulateAgent() {
        launchSimulation("agent")
    }

    @objc private func simulateCredentials() {
        launchSimulation("credentials")
    }

    private func launchSimulation(_ name: String) {
        // Run in Terminal.app so the user sees the 5 steps and can answer the
        // LAN-address prompt cleanly outside tmux/Claude Code.
        let escapedBin = tangentBin.replacingOccurrences(of: "'", with: "'\\''")
        let cmd = "'\(escapedBin)' simulate \(name)"
        let quoted = cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        // One window, whatever Terminal was doing. `activate` opens a window
        // of its own when Terminal has none, and `do script` then opened a
        // second: so the script goes first when Terminal is running, and
        // into the window Terminal starts with when it is not.
        let script = """
        if application "Terminal" is running then
            tell application "Terminal"
                do script "\(quoted)"
                activate
            end tell
        else
            tell application "Terminal"
                activate
                repeat 50 times
                    if (exists window 1) then exit repeat
                    delay 0.1
                end repeat
                if (exists window 1) then
                    do script "\(quoted)" in window 1
                else
                    do script "\(quoted)"
                end if
            end tell
        end if
        """
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        try? proc.run()
    }

    @objc private func openWatchLog() {
        let logPath = (watchDir as NSString).appendingPathComponent("watch.log")
        if FileManager.default.fileExists(atPath: logPath) {
            NSWorkspace.shared.open(URL(fileURLWithPath: logPath))
        } else {
            openDataFolder()
        }
    }

    @objc private func openDataFolder() {
        NSWorkspace.shared.open(URL(fileURLWithPath: watchDir))
    }

    @objc private func copyDiagnostics() {
        let s = currentStatus
        let lines = [
            "Tangent status: \(s?.isAlive == true ? (s?.state ?? "watching") : (s?.state ?? "stopped"))",
            "Models: \(s?.models ?? "unknown")",
            "Checked: \(s?.checked ?? 0), Flagged: \(s?.flagged ?? 0), Pending: \(s?.pending ?? 0)",
            "Sensor daemon socket: \(daemonConnected ? "present" : "absent")",
            "Needs FDA: \(s?.needsFda == true ? "yes" : "no")",
            "Data dir: \(watchDir)",
        ]
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }

    /// Quit is the whole of Tangent: the watch and this icon, as `tangent
    /// down --all` stops them. launchd keeps the menu bar running, so one
    /// that only ended itself would be back in a few seconds, and "Pause
    /// Watching" is there for stopping the watch alone. Stopping the menu
    /// bar's agent ends this process, and the command with it, which by then
    /// has done what it was run for.
    @objc private func quitTangent() {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: tangentBin)
        proc.arguments = ["down", "--all"]
        proc.standardInput = FileHandle.nullDevice
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        // without a tangent to run, at least this icon goes
        if (try? proc.run()) == nil {
            NSApp.terminate(nil)
        }
    }
}

// MARK: args & single-instance entrypoint

private func defaultWatchDir() -> String {
    let env = ProcessInfo.processInfo.environment
    if let xdg = env["XDG_DATA_HOME"], xdg.hasPrefix("/") {
        return (xdg as NSString).appendingPathComponent("tangent/mac")
    }
    return (NSHomeDirectory() as NSString).appendingPathComponent(".local/share/tangent/mac")
}

private func findTangentBinary() -> String {
    let candidates = [
        "/opt/homebrew/bin/tangent",
        "/usr/local/bin/tangent",
        (NSHomeDirectory() as NSString).appendingPathComponent(".cargo/bin/tangent"),
        (NSHomeDirectory() as NSString).appendingPathComponent(".local/bin/tangent"),
    ]
    for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
        return path
    }
    return "/usr/local/bin/tangent"
}

private var menuBarLockFd: Int32 = -1

/// Holds an exclusive lock on `<dir>/menubar.lock` so double-clicking
/// `Tangent.app` or restarting the LaunchAgent never spawns duplicate icons.
private func acquireMenuBarLock(in dir: String) -> Bool {
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let lockPath = (dir as NSString).appendingPathComponent("menubar.lock")
    let fd = Darwin.open(lockPath, O_CREAT | O_RDWR, 0o600)
    guard fd >= 0 else { return true }
    if flock(fd, LOCK_EX | LOCK_NB) != 0 {
        Darwin.close(fd)
        return false
    }
    menuBarLockFd = fd
    return true
}

private var retainedMenuController: MenuBarController?

/// Attaches the menu bar controller to an already-running `NSApplication`
/// (used when the user opens `Tangent.app` directly from Finder/Spotlight).
/// When a menu bar instance is already running, asks it to bring the Tangent
/// window forward and returns false so this process can exit cleanly.
func startMenuBarInRunningApp() -> Bool {
    let watchDir = defaultWatchDir()
    guard acquireMenuBarLock(in: watchDir) else {
        DistributedNotificationCenter.default().postNotificationName(
            openWindowNotification,
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
        return false
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let controller = MenuBarController(watchDir: watchDir, tangentBin: findTangentBinary())
    retainedMenuController = controller
    app.delegate = controller
    controller.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification))
    controller.openMainWindow()
    return true
}

/// Entrypoint for `tangent-sensor menubar [--open]`.
func runMenuBar() -> Never {
    var watchDir = defaultWatchDir()
    var tangentBin = findTangentBinary()
    var openWindow = false
    let args = Array(CommandLine.arguments.dropFirst(2))
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--dir":
            if i + 1 < args.count { watchDir = args[i + 1]; i += 2 } else { i += 1 }
        case "--tangent":
            if i + 1 < args.count { tangentBin = args[i + 1]; i += 2 } else { i += 1 }
        case "--open":
            openWindow = true
            i += 1
        default:
            i += 1
        }
    }

    guard acquireMenuBarLock(in: watchDir) else {
        // Another menu bar instance is already running.
        if openWindow {
            DistributedNotificationCenter.default().postNotificationName(
                openWindowNotification,
                object: nil,
                userInfo: nil,
                deliverImmediately: true
            )
        }
        exit(0)
    }

    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let controller = MenuBarController(watchDir: watchDir, tangentBin: tangentBin)
    retainedMenuController = controller
    app.delegate = controller
    if openWindow {
        DispatchQueue.main.async { controller.openMainWindow() }
    }
    app.run()
    exit(0)
}
