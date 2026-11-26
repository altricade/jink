// The app's state against a fake daemon whose watch streams and answers
// the tests control.

import JinkClient
import JinkProtocol
@testable import JinkUI
import Testing
import os

/// A daemon in memory: each watch is a stream the test feeds (or that fails
/// at once while `down`), and each request gets `answer`'s reply.
private final class FakeLink: DaemonLink {
    private struct State {
        var watches: [AsyncThrowingStream<Message, any Error>.Continuation] = []
        var sent: [Request] = []
        var down = false
        var answer: @Sendable (Request) -> Result<Message, ClientError> = { _ in .success(.done) }
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    func send(_ request: Request) async throws(ClientError) -> Message {
        let answer = state.withLock { state in
            state.sent.append(request)
            return state.answer
        }
        return try answer(request).get()
    }

    func watch() -> AsyncThrowingStream<Message, any Error> {
        let (stream, continuation) = AsyncThrowingStream<Message, any Error>.makeStream()
        let down = state.withLock { state in
            state.watches.append(continuation)
            return state.down
        }
        if down {
            continuation.finish(throwing: ClientError.noDaemon(detail: "No such file or directory"))
        }
        return stream
    }

    /// Sends `message` on the latest watch.
    func push(_ message: Message) {
        _ = state.withLock { $0.watches.last }?.yield(message)
    }

    /// Ends the latest watch, as a daemon that stops.
    func hangUp() {
        state.withLock { $0.watches.last }?.finish()
    }

    var watches: Int { state.withLock { $0.watches.count } }
    var sent: [Request] { state.withLock { $0.sent } }

    func setDown(_ down: Bool) {
        state.withLock { $0.down = down }
    }

    func answer(_ answer: @escaping @Sendable (Request) -> Result<Message, ClientError>) {
        state.withLock { $0.answer = answer }
    }
}

/// A service that installs as told, and remembers what it was asked.
private final class FakeService: ServiceControl {
    private let state = OSAllocatedUnfairLock<(calls: [String], result: Result<Void, ServiceError>)>(
        initialState: ([], .success(()))
    )

    func install() async throws(ServiceError) {
        try record("install")
    }

    func uninstall() async throws(ServiceError) {
        try record("uninstall")
    }

    private func record(_ call: String) throws(ServiceError) {
        let result = state.withLock { state in
            state.calls.append(call)
            return state.result
        }
        try result.get()
    }

    var calls: [String] { state.withLock { $0.calls } }

    func fail(with error: ServiceError) {
        state.withLock { $0.result = .failure(error) }
    }
}

private let strategies: [StrategyInfo] = [
    StrategyInfo(id: "general", name: "general", variantOf: nil, support: .partial),
    StrategyInfo(id: "alt", name: "ALT", variantOf: nil, support: .full),
    StrategyInfo(id: "alt6", name: "ALT6", variantOf: "general", support: .partial),
    StrategyInfo(id: "orphan", name: "Orphan", variantOf: "gone", support: .full),
]

private let settings = Settings(
    mySites: ["www.youtube.com"],
    myIps: [],
    excludedSites: [],
    excludedIps: [],
    gaming: Gaming(mode: .off, tcpPorts: "1024-65535", udpPorts: "1024-65535"),
    ipList: .off
)

/// The daemon's usual answers.
@Sendable private func usual(_ request: Request) -> Result<Message, ClientError> {
    switch request {
    case .strategies: .success(.strategies(strategies))
    case .settings: .success(.settings(settings))
    default: .success(.done)
    }
}

private func status(_ engine: Engine, version: String = "0.1.0") -> Message {
    .status(Status(engine: engine, strategy: "alt", startAtBoot: false, version: version, found: nil))
}

/// Waits (up to two seconds) until `condition` holds.
@MainActor
private func eventually(_ condition: () -> Bool) async throws -> Bool {
    for _ in 0..<200 {
        if condition() { return true }
        try await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

/// A model following `link`, and the task that runs it.
@MainActor
private func following(_ link: FakeLink) -> (AppModel, Task<Void, Never>) {
    let model = AppModel(daemon: link, service: FakeService(), bundledVersion: "0.1.0", retry: .milliseconds(20))
    return (model, Task { await model.run() })
}

@MainActor
@Test func connectingLoadsTheStrategiesAndSettings() async throws {
    let link = FakeLink()
    link.answer(usual)
    let (model, task) = following(link)
    defer { task.cancel() }
    #expect(model.connection == .connecting)
    #expect(try await eventually { link.watches == 1 })
    link.push(status(.off))
    #expect(try await eventually { model.settings != nil })
    #expect(model.strategies == strategies)
    #expect(model.settings == settings)
    #expect(!model.needsReinstall)
    // Variants under their main strategy; one whose main is unknown alone.
    #expect(model.groups.map(\.id) == ["general", "alt", "orphan"])
    #expect(model.groups.first?.variants.map(\.id) == ["alt6"])
    // Loaded once per connection, not at every update.
    link.push(status(.starting))
    #expect(try await eventually { model.status?.engine == .starting })
    #expect(link.sent == [.strategies, .settings])
}

@MainActor
@Test func withoutTheDaemonItKeepsTrying() async throws {
    let link = FakeLink()
    link.answer(usual)
    link.setDown(true)
    let (model, task) = following(link)
    defer { task.cancel() }
    #expect(try await eventually { model.connection == .noDaemon(detail: "No such file or directory") })
    #expect(try await eventually { link.watches >= 2 })
    #expect(model.indicator == .off)
    link.setDown(false)
    let tries = link.watches
    #expect(try await eventually { link.watches > tries })
    link.push(status(.off))
    #expect(try await eventually { model.status != nil })

    // The daemon stops: no daemon, then back, loading again.
    link.hangUp()
    #expect(try await eventually {
        if case .noDaemon = model.connection { true } else { false }
    })
    let again = link.watches
    #expect(try await eventually { link.watches > again })
    link.push(status(.off))
    #expect(try await eventually { link.sent.count == 4 })
    #expect(link.sent == [.strategies, .settings, .strategies, .settings])
}

@MainActor
@Test func theIconAndSwitchFollowTheEngine() async throws {
    let link = FakeLink()
    link.answer(usual)
    let (model, task) = following(link)
    defer { task.cancel() }
    #expect(try await eventually { link.watches == 1 })
    let problem = Problem(code: "x", detail: "y")
    let cases: [(Engine, Indicator, Bool, Bool)] = [
        (.off, .off, false, false),
        (.starting, .busy, true, false),
        (.on(.checking), .busy, true, false),
        (.on(.online(uplink: "en0", ipv6: false)), .on, true, false),
        (.on(.offline), .trouble, true, false),
        (.on(.bypassed(problem)), .trouble, true, false),
        (.failed(problem), .trouble, false, false),
        (.finding(step: 2, of: 14, strategy: "alt"), .busy, false, true),
    ]
    for (engine, indicator, on, finding) in cases {
        link.push(status(engine))
        #expect(try await eventually { model.status?.engine == engine })
        #expect(model.indicator == indicator, "\(engine)")
        #expect(model.isOn == on, "\(engine)")
        #expect(model.isFinding == finding, "\(engine)")
    }
    // Notices are kept; another version of the service asks for a reinstall.
    link.push(.notice(problem))
    link.push(status(.off, version: "0.0.9"))
    #expect(try await eventually { model.needsReinstall })
    #expect(model.notice == problem)
}

@MainActor
@Test func actionsSendTheirRequests() async {
    let link = FakeLink()
    let model = AppModel(daemon: link, service: FakeService(), bundledVersion: "0.1.0")
    await model.setOn(true)
    await model.setOn(false)
    await model.choose("alt4")
    await model.find()
    await model.cancelFind()
    await model.setStartAtBoot(true)
    #expect(link.sent == [
        .start(strategy: nil), .stop, .start(strategy: "alt4"), .find, .cancelFind, .setStartAtBoot(true),
    ])
    #expect(model.trouble == nil)
}

@MainActor
@Test func failedRequestsAreShownOnce() async {
    let link = FakeLink()
    let model = AppModel(daemon: link, service: FakeService(), bundledVersion: "0.1.0")
    link.answer { _ in .success(.error(.unknownStrategy("alt99"))) }
    await model.choose("alt99")
    #expect(model.trouble == .refused(.unknownStrategy("alt99")))
    model.dismissTrouble()
    #expect(model.trouble == nil)
    link.answer { _ in .failure(.closed) }
    await model.find()
    #expect(model.trouble == .client(.closed))
    link.answer { _ in .success(.strategies([])) }
    await model.find()
    #expect(model.trouble == .unexpected)
    // A cancelled request is no trouble.
    model.dismissTrouble()
    link.answer { _ in .failure(.cancelled) }
    await model.find()
    #expect(model.trouble == nil)
}

@MainActor
@Test func settingsAreSavedOrTheirProblemsListed() async {
    let link = FakeLink()
    let model = AppModel(daemon: link, service: FakeService(), bundledVersion: "0.1.0")
    let problems = [SettingsProblem(field: "my_sites", index: 0, code: "no_dot")]
    link.answer { request in
        switch request {
        case .updateSettings: .success(.error(.invalidSettings(problems)))
        default: usual(request)
        }
    }
    var edited = settings
    edited.mySites = ["youtube"]
    #expect(await model.save(edited) == problems)
    #expect(model.trouble == nil)
    #expect(model.settings == nil)

    // Saved: the daemon's normalized settings are shown.
    link.answer(usual)
    edited.mySites = ["https://www.youtube.com/watch"]
    #expect(await model.save(edited) == [])
    #expect(model.settings == settings)
    #expect(link.sent.suffix(2) == [.updateSettings(edited), .settings])

    link.answer { _ in .success(.error(.failed(detail: "disk full"))) }
    #expect(await model.save(edited) == [])
    #expect(model.trouble == .refused(.failed(detail: "disk full")))
}

@MainActor
@Test func theServiceIsInstalledAndRemoved() async {
    let service = FakeService()
    let model = AppModel(daemon: FakeLink(), service: service, bundledVersion: "0.1.0")
    await model.installService()
    await model.uninstallService()
    #expect(service.calls == ["install", "uninstall"])
    #expect(model.serviceWork == nil)
    #expect(model.serviceError == nil)
    // Cancelling the password prompt is no error; a failure is shown.
    service.fail(with: .cancelled)
    await model.installService()
    #expect(model.serviceError == nil)
    service.fail(with: .failed(detail: "launchctl: no"))
    await model.installService()
    #expect(model.serviceError == .failed(detail: "launchctl: no"))
    #expect(model.serviceWork == nil)
}

@Test func pathsAreQuotedForAppleScript() {
    // The app may sit in a folder with quotes or backslashes in its name.
    #expect(appleScriptString(#"/Apps/My "jink"\x/jink"#) == #""/Apps/My \"jink\"\\x/jink""#)
}
