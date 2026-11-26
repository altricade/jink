// Installing jink's background service: the `jink` command bundled with the
// app runs `service install` (or `uninstall`) as root, after the system
// asks for an administrator's password.

public import Foundation

/// Why installing or removing the service failed.
public enum ServiceError: Error, Equatable, Sendable {
    /// The person cancelled the password prompt.
    case cancelled
    /// The app has no `jink` command inside (a broken build).
    case missing
    /// It ran and failed; `detail` is what it said.
    case failed(detail: String)
}

/// Installs and removes the background service.
public protocol ServiceControl: Sendable {
    func install() async throws(ServiceError)
    func uninstall() async throws(ServiceError)
}

/// Runs the bundled `jink` as root through `osascript`, which shows the
/// system's password prompt.
public struct BundledService: ServiceControl {
    /// The `jink` command inside the app, if there is one.
    let command: URL?

    public init(command: URL?) {
        self.command = command
    }

    public func install() async throws(ServiceError) {
        try await run("service install")
    }

    public func uninstall() async throws(ServiceError) {
        try await run("service uninstall")
    }

    private func run(_ arguments: String) async throws(ServiceError) {
        guard let command else { throw .missing }
        let script = "do shell script quoted form of \(appleScriptString(command.path)) & \" \(arguments)\" with administrator privileges"
        let (status, output) = await osascript(script)
        switch status {
        case 0: return
        // -128: "User canceled."
        case _ where output.contains("(-128)"): throw .cancelled
        default: throw .failed(detail: output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}

/// `text` as an AppleScript string literal.
func appleScriptString(_ text: String) -> String {
    let escaped = text
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
    return "\"\(escaped)\""
}

/// Runs `script` and gives its exit status and error output, without
/// blocking a thread while it waits (the password prompt may stay open).
private func osascript(_ script: String) async -> (Int32, String) {
    let process = Process()
    process.executableURL = URL(filePath: "/usr/bin/osascript")
    process.arguments = ["-e", script]
    let errors = Pipe()
    process.standardError = errors
    process.standardOutput = FileHandle.nullDevice
    return await withCheckedContinuation { continuation in
        process.terminationHandler = { finished in
            let output = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            continuation.resume(returning: (finished.terminationStatus, output))
        }
        do {
            try process.run()
        } catch {
            process.terminationHandler = nil
            continuation.resume(returning: (-1, error.localizedDescription))
        }
    }
}
