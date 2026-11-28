// keychain.swift: macOS Keychain broker inside `Tangent.app`.
//
//   tangent-sensor key list               # prints stored env var names (no secret read)
//   tangent-sensor key set <NAME>         # reads secret value from stdin, stores in Keychain
//   tangent-sensor key get <NAME>         # prints secret value to stdout
//   tangent-sensor key dump               # prints NAME=VALUE lines for every stored secret
//   tangent-sensor key clear <NAME>       # deletes one entry
//   tangent-sensor key clear-all          # deletes all entries for Tangent
//
// Keeping all Keychain reads and writes inside the Developer-ID-signed
// `Tangent.app` bundle avoids macOS ACL prompts from an unsigned CLI binary
// and keeps API keys out of plaintext files, plists, argv, and `ps`.

import Foundation
import Security

enum KeychainError: LocalizedError {
    case invalidName(String)
    case locked
    case osStatus(OSStatus, String)

    var errorDescription: String? {
        switch self {
        case .invalidName(let name):
            return "invalid key name: \(name)"
        case .locked:
            return "macOS Login Keychain is locked — unlock your Mac to read Tangent API keys"
        case .osStatus(let status, let op):
            if let msg = SecCopyErrorMessageString(status, nil) as String? {
                return "Keychain \(op) failed (\(status)): \(msg)"
            }
            return "Keychain \(op) failed (OSStatus \(status))"
        }
    }
}

enum KeychainStore {
    static var service: String {
        if let override = ProcessInfo.processInfo.environment["TANGENT_KEYCHAIN_SERVICE"],
           !override.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return override
        }
        return "com.ethanblackburn.tangent"
    }

    static func validateName(_ name: String) throws {
        guard !name.isEmpty,
              name.unicodeScalars.allSatisfy({
                  ($0 >= "A" && $0 <= "Z") || ($0 >= "0" && $0 <= "9") || $0 == "_"
              })
        else {
            throw KeychainError.invalidName(name)
        }
    }

    /// Lists stored account names using attributes only (never decrypts secrets
    /// and never triggers a Keychain unlock prompt).
    static func list() throws -> [String] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, "list")
        }
        guard let items = result as? [[CFString: Any]] else {
            return []
        }
        return items
            .compactMap { $0[kSecAttrAccount] as? String }
            .sorted()
    }

    /// Reads one secret value from the Login Keychain, or `nil` if absent.
    static func get(account: String) throws -> String? {
        try validateName(account)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecReturnData: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        if status == errSecInteractionNotAllowed {
            throw KeychainError.locked
        }
        guard status == errSecSuccess else {
            throw KeychainError.osStatus(status, "read \(account)")
        }
        guard let data = result as? Data else {
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }

    /// Stores or updates a secret in the Login Keychain. Updates in place when
    /// present so existing ACLs are preserved.
    static func set(account: String, value: String) throws {
        try validateName(account)
        let clean = value
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        if clean.isEmpty {
            try clear(account: account)
            return
        }
        let secretData = Data(clean.utf8)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let updateAttrs: [CFString: Any] = [
            kSecValueData: secretData,
            kSecAttrLabel: "Tangent (\(account))",
        ]
        let updated = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updated == errSecSuccess {
            return
        }
        if updated == errSecInteractionNotAllowed {
            throw KeychainError.locked
        }
        if updated != errSecItemNotFound {
            throw KeychainError.osStatus(updated, "update \(account)")
        }

        var addQuery = query
        addQuery[kSecValueData] = secretData
        addQuery[kSecAttrLabel] = "Tangent (\(account))"
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
        let added = SecItemAdd(addQuery as CFDictionary, nil)
        if added == errSecInteractionNotAllowed {
            throw KeychainError.locked
        }
        guard added == errSecSuccess else {
            throw KeychainError.osStatus(added, "store \(account)")
        }
    }

    /// Deletes one entry from the Login Keychain.
    static func clear(account: String) throws {
        try validateName(account)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        throw KeychainError.osStatus(status, "delete \(account)")
    }

    /// Deletes every Tangent entry from the Login Keychain.
    static func clearAll() throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        throw KeychainError.osStatus(status, "clear all")
    }

    /// Reads all stored secrets as `(account, value)` pairs.
    static func dump() throws -> [(String, String)] {
        let names = try list()
        var out: [(String, String)] = []
        for name in names {
            if let value = try get(account: name) {
                out.append((name, value))
            }
        }
        return out
    }
}

/// Entrypoint for `tangent-sensor key <subcommand>`.
func runKeyCommand() -> Never {
    let args = Array(CommandLine.arguments.dropFirst(2))
    guard let sub = args.first else {
        fail("usage: tangent-sensor key <list|get|set|dump|clear|clear-all> [NAME]")
    }
    do {
        switch sub {
        case "list":
            for name in try KeychainStore.list() {
                print(name)
            }
        case "get":
            guard args.count == 2 else { fail("usage: tangent-sensor key get <NAME>") }
            guard let val = try KeychainStore.get(account: args[1]) else {
                exit(2)
            }
            print(val, terminator: "")
        case "set":
            guard args.count == 2 else { fail("usage: tangent-sensor key set <NAME>") }
            let stdinData = FileHandle.standardInput.readDataToEndOfFile()
            let val = String(decoding: stdinData, as: UTF8.self)
            try KeychainStore.set(account: args[1], value: val)
        case "dump":
            for (name, val) in try KeychainStore.dump() {
                print("\(name)=\(val)")
            }
        case "clear":
            guard args.count == 2 else { fail("usage: tangent-sensor key clear <NAME>") }
            try KeychainStore.clear(account: args[1])
        case "clear-all":
            try KeychainStore.clearAll()
        default:
            fail("unknown key subcommand: \(sub)")
        }
        exit(0)
    } catch {
        fail(error.localizedDescription)
    }
}
