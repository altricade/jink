// The app's state: what the daemon says, kept current by watching it, and
// the actions the views take. Views only read this and call its methods.

public import JinkClient
public import JinkProtocol
public import Observation

/// What the app talks to: the daemon ([`DaemonClient`]); a fake in tests.
public protocol DaemonLink: Sendable {
    func send(_ request: Request) async throws(ClientError) -> Message
    func watch() -> AsyncThrowingStream<Message, any Error>
}

extension DaemonClient: DaemonLink {}

/// Whether the app reaches the daemon.
public enum Connection: Equatable, Sendable {
    case connecting
    /// The service is not installed or not running; `detail` is the
    /// system's text.
    case noDaemon(detail: String)
    case connected(Status)
}

/// A main strategy and its variants, as the picker shows them.
public struct StrategyGroup: Equatable, Sendable, Identifiable {
    public var main: StrategyInfo
    public var variants: [StrategyInfo]
    public var id: String { main.id }
}

/// What the menu-bar icon shows.
public enum Indicator: Equatable, Sendable {
    /// Desync is off (or the daemon is not there).
    case off
    /// Starting, checking the network, or finding a strategy.
    case busy
    case on
    /// On but not working (offline, bypassed), or failed.
    case trouble
}

/// Work on the background service.
public enum ServiceWork: Equatable, Sendable {
    case installing
    case uninstalling
}

/// What the last request that failed said (the views show it once).
public enum Trouble: Equatable, Sendable {
    case client(ClientError)
    case refused(Failure)
    /// The daemon answered with something that does not answer the request.
    case unexpected
}

@MainActor
@Observable
public final class AppModel {
    public private(set) var connection: Connection = .connecting
    public private(set) var strategies: [StrategyInfo] = []
    public private(set) var settings: Settings?
    /// The latest notice since the app connected.
    public private(set) var notice: Problem?
    /// The latest failed request, until `dismissTrouble`.
    public private(set) var trouble: Trouble?
    /// Installing or removing the service, while it runs.
    public private(set) var serviceWork: ServiceWork?
    /// Why the latest install or removal failed, until the next one.
    public private(set) var serviceError: ServiceError?

    /// The version of the daemon this app bundles.
    public let bundledVersion: String

    private let daemon: any DaemonLink
    private let service: any ServiceControl
    private let retry: Duration

    /// Talks to `daemon`, installs it with `service` (which bundles a
    /// daemon of `bundledVersion`); while the daemon is unreachable, tries
    /// again every `retry`.
    public init(
        daemon: any DaemonLink,
        service: any ServiceControl,
        bundledVersion: String,
        retry: Duration = .seconds(2)
    ) {
        self.daemon = daemon
        self.service = service
        self.bundledVersion = bundledVersion
        self.retry = retry
    }

    /// The status, if connected.
    public var status: Status? {
        if case .connected(let status) = connection { status } else { nil }
    }

    public var indicator: Indicator {
        switch status?.engine {
        case nil, .off: .off
        case .starting, .finding, .on(.checking): .busy
        case .on(.online): .on
        case .on(.offline), .on(.bypassed), .failed: .trouble
        }
    }

    /// Whether desync is on or on its way (the switch's position).
    public var isOn: Bool {
        switch status?.engine {
        case .starting, .on: true
        case nil, .off, .failed, .finding: false
        }
    }

    public var isFinding: Bool {
        if case .finding = status?.engine { true } else { false }
    }

    /// The running service is another version than the one bundled.
    public var needsReinstall: Bool {
        status.map { $0.version != bundledVersion } ?? false
    }

    /// The strategies by main strategy, in the daemon's order; a variant
    /// whose main one is unknown stands alone.
    public var groups: [StrategyGroup] {
        let mains = Set(strategies.filter { $0.variantOf == nil }.map(\.id))
        return strategies
            .filter { $0.variantOf.map { !mains.contains($0) } ?? true }
            .map { main in
                StrategyGroup(main: main, variants: strategies.filter { $0.variantOf == main.id })
            }
    }

    /// Follows the daemon until the task is cancelled: connects, keeps the
    /// state current, and reconnects when it goes away.
    public func run() async {
        while !Task.isCancelled {
            await follow()
            guard !Task.isCancelled else { return }
            try? await Task.sleep(for: retry)
        }
    }

    /// One connection, until it ends.
    private func follow() async {
        var loaded = false
        do {
            for try await message in daemon.watch() {
                switch message {
                case .status(let status):
                    connection = .connected(status)
                    if !loaded {
                        loaded = true
                        await load()
                    }
                case .notice(let problem):
                    notice = problem
                case .strategies, .settings, .done, .error:
                    break
                }
            }
            connection = .noDaemon(detail: "the daemon closed the connection")
        } catch ClientError.noDaemon(let detail) {
            connection = .noDaemon(detail: detail)
        } catch {
            connection = .noDaemon(detail: String(describing: error))
        }
    }

    /// The strategies and settings, once per connection.
    private func load() async {
        if case .strategies(let strategies) = await ask(.strategies) {
            self.strategies = strategies
        }
        if case .settings(let settings) = await ask(.settings) {
            self.settings = settings
        }
    }

    /// Turns desync on (with the strategy used last) or off.
    public func setOn(_ on: Bool) async {
        await act(on ? .start(strategy: nil) : .stop)
    }

    /// Switches to `strategy` (turning desync on).
    public func choose(_ strategy: String) async {
        await act(.start(strategy: strategy))
    }

    public func find() async {
        await act(.find)
    }

    public func cancelFind() async {
        await act(.cancelFind)
    }

    public func setStartAtBoot(_ on: Bool) async {
        await act(.setStartAtBoot(on))
    }

    /// Saves `settings`; the invalid entries if any (then nothing changed).
    public func save(_ settings: Settings) async -> [SettingsProblem] {
        switch await send(.updateSettings(settings)) {
        case .done:
            // Sent back normalized (links become domains).
            if case .settings(let saved) = await ask(.settings) {
                self.settings = saved
            }
            return []
        case .error(.invalidSettings(let problems)):
            return problems
        case .error(let failure):
            trouble = .refused(failure)
            return []
        case nil:
            return []
        default:
            trouble = .unexpected
            return []
        }
    }

    public func dismissTrouble() {
        trouble = nil
    }

    /// Installs the service (or replaces it with the bundled version); the
    /// app connects to it by itself.
    public func installService() async {
        await serve(.installing) { () async throws(ServiceError) in try await service.install() }
    }

    /// Removes the service (desync stops).
    public func uninstallService() async {
        await serve(.uninstalling) { () async throws(ServiceError) in try await service.uninstall() }
    }

    private func serve(
        _ work: ServiceWork,
        _ run: () async throws(ServiceError) -> Void
    ) async {
        guard serviceWork == nil else { return }
        serviceWork = work
        serviceError = nil
        do throws(ServiceError) {
            try await run()
        } catch .cancelled {
            // The person changed their mind: no error to show.
        } catch {
            serviceError = error
        }
        serviceWork = nil
    }

    /// Sends `request`, which the daemon answers with `done`.
    private func act(_ request: Request) async {
        switch await ask(request) {
        case .done, nil: break
        default: trouble = .unexpected
        }
    }

    /// The daemon's answer, or `nil` with `trouble` set (an error answer
    /// included).
    private func ask(_ request: Request) async -> Message? {
        let answer = await send(request)
        if case .error(let failure) = answer {
            trouble = .refused(failure)
            return nil
        }
        return answer
    }

    /// The daemon's answer, or `nil` with `trouble` set if it could not be
    /// asked.
    private func send(_ request: Request) async -> Message? {
        do throws(ClientError) {
            return try await daemon.send(request)
        } catch .cancelled {
            return nil
        } catch {
            trouble = .client(error)
            return nil
        }
    }
}
