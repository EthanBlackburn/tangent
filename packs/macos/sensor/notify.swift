// What tangent-sensor does when it is not the sensor: it shows the
// notifications `tangent watch` asks for, the report behind one that is
// clicked, and keeps the answer its buttons give. All of it runs as the
// person at this Mac, never as root.
//
//   tangent-sensor notify < notifications.ndjson
//
// A notification has to come from an app: macOS shows it under the app's name
// and icon, asks its owner once whether the app may show any, and tells the
// app when one is clicked. The sensor's bundle is that app, signed and
// notarized already.
//
// Each line of stdin is one notification, a JSON object: `title`, `subtitle`
// and `body` are the banner, `detail` is the text shown when it is clicked,
// and `sound` says whether it makes one. With `feedback` it asks whether what
// it reports was its reader's doing, with three buttons: `feedback.file` is
// the file the answer is added to, and `feedback.line` the JSON object it is
// added as, with `answer` and `ts` put in. The text is a model's,
// written about records an attacker can write into: it is only ever shown,
// as text.

import AppKit
import Foundation
import UserNotifications

/// macOS's notifications for this app. They are kept by bundle, so a binary
/// that is not in one has none.
func notifications() -> UNUserNotificationCenter {
    guard Bundle.main.bundleIdentifier != nil else {
        fail("notifications come from an app, and this binary is not inside one: run Tangent.app/Contents/MacOS/tangent-sensor")
    }
    return UNUserNotificationCenter.current()
}

// MARK: the answer

/// What a notification with `feedback` asks, as its buttons, and what each
/// is written as.
let answers = [(written: "not_mine", button: "Not me"), (written: "unsure", button: "Not sure"), (written: "mine", button: "That was me")]

/// The kind of notification that has the buttons.
let asks = "asks"

/// Tells macOS of the buttons. It keeps them with the app, for a
/// notification shown by a process that has since ended.
func registerAnswers(_ center: UNUserNotificationCenter) {
    let buttons = answers.map { UNNotificationAction(identifier: $0.written, title: $0.button, options: []) }
    center.setNotificationCategories([
        UNNotificationCategory(identifier: asks, actions: buttons, intentIdentifiers: [], options: [])
    ])
}

/// Adds the answer to the file its notification named, as the line it gave
/// with `answer` and the time put in.
func keep(_ answer: String, for info: [AnyHashable: Any]) {
    guard let file = info["file"] as? String, let given = info["line"] as? String,
        var line = (try? JSONSerialization.jsonObject(with: Data(given.utf8))) as? [String: Any]
    else { return }
    line["ts"] = ISO8601DateFormatter().string(from: Date())
    line["answer"] = answer
    guard var data = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys, .withoutEscapingSlashes])
    else { return }
    data.append(0x0A)
    // one write to the end of the file, so two answers at once are two lines
    let fd = open(file, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0 else { return warn("the answer was not kept: \(file): \(String(cString: strerror(errno)))") }
    _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
    close(fd)
}

// MARK: the click

/// The dialogs that are up. A process that showed one waits for its answer
/// before it ends.
let asking = DispatchGroup()

/// The report behind a notification, in a dialog of macOS's own: the whole
/// finding, and when the notification asks, its three buttons. It waits for
/// the dialog to be closed.
func report(_ content: UNNotificationContent) {
    let info = content.userInfo
    let detail = info["detail"] as? String ?? ""
    var said: [CFString: Any] = [
        kCFUserNotificationAlertHeaderKey: [content.title, content.subtitle].filter { !$0.isEmpty }.joined(separator: "\n"),
        kCFUserNotificationAlertMessageKey: detail.isEmpty ? content.body : detail,
    ]
    if let icon = Bundle.main.url(forResource: "AppIcon", withExtension: "icns") {
        said[kCFUserNotificationIconURLKey] = icon
    }
    let asked = info["file"] != nil
    if asked {
        // the dialog's three places, in the order CFUserNotification answers by
        said[kCFUserNotificationDefaultButtonTitleKey] = answers[1].button
        said[kCFUserNotificationAlternateButtonTitleKey] = answers[2].button
        said[kCFUserNotificationOtherButtonTitleKey] = answers[0].button
    }
    var error: Int32 = 0
    guard let dialog = CFUserNotificationCreate(nil, 0, kCFUserNotificationNoteAlertLevel, &error, said as CFDictionary)
    else { return warn("the report was not shown (\(error))") }
    var response: CFOptionFlags = 0
    guard CFUserNotificationReceiveResponse(dialog, 0, &response) == 0, asked else { return }
    let pressed: String
    switch response & 0x3 {
    case UInt(kCFUserNotificationDefaultResponse): pressed = answers[1].written
    case UInt(kCFUserNotificationAlternateResponse): pressed = answers[2].written
    case UInt(kCFUserNotificationOtherResponse): pressed = answers[0].written
    default: return  // closed some other way: no answer
    }
    keep(pressed, for: info)
}

/// What a click on a notification does: one of its buttons keeps that
/// answer, and the banner itself opens the report.
final class Clicks: NSObject, UNUserNotificationCenterDelegate {
    /// Called when a click has been dealt with.
    var dealt: () -> Void = {}

    func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler done: @escaping () -> Void
    ) {
        noClick.cancel()
        let content = response.notification.request.content
        let action = response.actionIdentifier
        if action == UNNotificationDefaultActionIdentifier {
            asking.enter()
            DispatchQueue.global().async {
                report(content)
                asking.leave()
                self.dealt()
            }
        } else {
            if answers.contains(where: { $0.written == action }) {
                keep(action, for: content.userInfo)
            }
            dealt()
        }
        done()
    }
}

let clicks = Clicks()

// MARK: notify

/// Tangent's own page of System Settings, Notifications, where its switch is.
func openSettings() {
    guard let id = Bundle.main.bundleIdentifier else { return }
    let open = Process()
    open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    open.arguments = ["x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(id)"]
    guard (try? open.run()) != nil else { return }
    open.waitUntilExit()
}

/// Whether this Mac's owner allows Tangent's notifications: asked the first
/// time, and read from macOS after that, since macOS asks an app only once.
/// Calls `go` when they are allowed. When they are not it says why and
/// ends, and an owner who said no before has System Settings opened at
/// Tangent's switch: nothing else can ask them again.
func allowed(_ center: UNUserNotificationCenter, then go: @escaping () -> Void) {
    // on a queue of its own: `go` waits for each notification to be added,
    // and macOS says so on the queue these answers come on, which waits
    // behind whatever is still running there
    let show = { DispatchQueue.global().async(execute: go) }
    center.getNotificationSettings { settings in
        switch settings.authorizationStatus {
        case .authorized, .provisional:
            show()
        case .denied:
            openSettings()
            fail("this Mac does not allow Tangent's notifications: System Settings is open at them, where Allow notifications turns them on")
        default:  // not asked yet
            center.requestAuthorization(options: [.alert, .sound]) { yes, error in
                // macOS refusing to ask is not the owner saying no: an app
                // that is not signed, or not one bundle, is never asked about
                if let error {
                    fail("macOS would not ask whether Tangent may show notifications (\(error.localizedDescription)): the app has to be signed, as ./build.sh signs it")
                }
                guard yes else {
                    fail("Tangent's notifications were not allowed: System Settings, Notifications, Tangent turns them on")
                }
                show()
            }
        }
    }
}

/// `tangent-sensor notify`: asks, the first time, whether this Mac's owner
/// allows the notifications ([`allowed`]), and shows one for each line of
/// stdin, until stdin ends. macOS takes its question back when the process
/// that asked ends, and counts that as a no, so this waits for the answer as
/// long as it is let run. It stops at once, and says so, when the answer is
/// no.
func notify() -> Never {
    let center = notifications()
    center.delegate = clicks
    registerAnswers(center)
    allowed(center) {
        while let line = readLine() {
            guard let note = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] else {
                continue
            }
            let text = { (key: String) in note[key] as? String ?? "" }
            let content = UNMutableNotificationContent()
            content.title = text("title")
            content.subtitle = text("subtitle")
            content.body = text("body")
            var info = ["detail": text("detail")]
            if let feedback = note["feedback"] as? [String: Any], let file = feedback["file"] as? String,
                let line = feedback["line"] as? [String: Any],
                let kept = try? JSONSerialization.data(withJSONObject: line)
            {
                info["file"] = file
                info["line"] = String(decoding: kept, as: UTF8.self)
                content.categoryIdentifier = asks
            }
            content.userInfo = info
            if note["sound"] as? Bool == true { content.sound = .default }
            let added = DispatchSemaphore(value: 0)
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) { error in
                if let error { warn("a notification was not shown: \(error.localizedDescription)") }
                added.signal()
            }
            added.wait()
        }
        // a report that is open is answered first
        asking.wait()
        exit(0)
    }
    dispatchMain()
}

// MARK: opened by macOS

/// Whether macOS started this as an app, which is what it does when a
/// notification is clicked and the process that showed it has ended. It
/// names the app it starts in the environment; a shell names its terminal
/// there, and sudo nothing.
func openedByMacOS() -> Bool {
    guard let id = Bundle.main.bundleIdentifier else { return false }
    return ProcessInfo.processInfo.environment["__CFBundleIdentifier"] == id
}

/// How long an app macOS started waits to be told which notification was
/// clicked, before it takes it that none was.
let clickWithin = 10.0
let noClick = DispatchWorkItem { exit(0) }

/// How long the installed app waits for that click before it takes it that
/// it was opened from Finder or Spotlight, and shows the menu bar. A click
/// that comes later is still dealt with, by the menu bar.
let menuAfter = 1.0

/// Where `tangent up` puts the app (`INSTALLED_DIR` in crates/shared). Only
/// that copy has a menu bar to show: the one `tangent watch mac` keeps in its
/// cache is opened by macOS for a click and for nothing else, and a click
/// that is slow to come must not leave an icon nobody asked for.
let installedApp = "/Applications/Tangent.app"

/// The notification centre's delegate is weak, and a local is let go after
/// its last use: this is what keeps the one `opened` sets.
private var clickDelegate: ClickOrMenuDelegate?

/// Started by macOS: either a notification was clicked after `notify` ended,
/// or the user opened `Tangent.app` directly from Finder / Spotlight. A click
/// is dealt with and the process ends. Without one, the installed app shows
/// the menu bar unless one is up already, and any other copy ends.
func opened() -> Never {
    var gotClick = false
    clicks.dealt = { exit(0) }
    let center = notifications()
    registerAnswers(center)
    let launchMenu = DispatchWorkItem {
        guard !gotClick else { return }
        // Another menu bar is up: this one goes on waiting for its click.
        if startMenuBarInRunningApp() { noClick.cancel() }
    }
    // Wrap clicks to mark `gotClick` as soon as a response arrives.
    let watcher = ClickOrMenuDelegate(
        onClick: { gotClick = true; launchMenu.cancel() }
    )
    clickDelegate = watcher
    center.delegate = watcher
    if Bundle.main.bundlePath == installedApp {
        DispatchQueue.main.asyncAfter(deadline: .now() + menuAfter, execute: launchMenu)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + clickWithin, execute: noClick)
    NSApplication.shared.run()
    exit(0)
}

private final class ClickOrMenuDelegate: NSObject, UNUserNotificationCenterDelegate {
    let onClick: () -> Void
    init(onClick: @escaping () -> Void) { self.onClick = onClick }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler done: @escaping () -> Void
    ) {
        onClick()
        clicks.userNotificationCenter(center, didReceive: response, withCompletionHandler: done)
    }
}
