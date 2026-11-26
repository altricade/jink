// What the daemon sends: one `Message` per line. Mirrors
// `crates/jink-daemon/src/protocol.rs`; `contract/messages` has an example
// of each, which the tests decode.

/// A message from the daemon: the answer to one request, or an update on a
/// watching connection.
public enum Message: Sendable, Equatable {
    case status(Status)
    case strategies([StrategyInfo])
    case settings(Settings)
    case done
    case error(Failure)
    /// Something that went wrong without changing the state, each kind once
    /// per start.
    case notice(Problem)
}

public struct Status: Sendable, Equatable, Decodable {
    public var engine: Engine
    /// The strategy desync runs (or last ran) with.
    public var strategy: String
    public var startAtBoot: Bool
    /// The daemon's version.
    public var version: String
    /// What the last finding found (since the daemon started).
    public var found: Found?

    public init(engine: Engine, strategy: String, startAtBoot: Bool, version: String, found: Found?) {
        self.engine = engine
        self.strategy = strategy
        self.startAtBoot = startAtBoot
        self.version = version
        self.found = found
    }
}

/// Whether desync runs.
public enum Engine: Sendable, Equatable {
    case off
    case starting
    case on(Network)
    /// It stopped by itself or could not start.
    case failed(Problem)
    /// Finding a strategy: at `step` of `of`, trying `strategy` (none at the
    /// first step, which checks the sites without jink).
    case finding(step: Int, of: Int, strategy: String?)
}

/// The network while desync is on.
public enum Network: Sendable, Equatable {
    /// Just started.
    case checking
    /// Traffic goes through jink and leaves through `uplink`; with `ipv6`,
    /// the network has IPv6, turned away so that apps use IPv4.
    case online(uplink: String, ipv6: Bool)
    /// Traffic on every network goes through jink (Windows only).
    case active
    /// No network; jink waits for one.
    case offline
    /// jink cannot work on this network, so traffic goes around it.
    case bypassed(Problem)
}

/// A problem: a stable `code` that the app explains in its language, and
/// the system's own (English) text as `detail`.
public struct Problem: Sendable, Equatable, Decodable {
    public var code: String
    public var detail: String

    public init(code: String, detail: String) {
        self.code = code
        self.detail = detail
    }
}

public struct StrategyInfo: Sendable, Equatable, Decodable, Identifiable {
    public var id: String
    public var name: String
    /// The main strategy this one is a variant of.
    public var variantOf: String?
    public var support: Support

    public init(id: String, name: String, variantOf: String?, support: Support) {
        self.id = id
        self.name = name
        self.variantOf = variantOf
        self.support = support
    }
}

/// How much of a strategy this computer can run.
public enum Support: String, Sendable, Equatable, Decodable {
    case full
    /// Some of its rules pass traffic unchanged here.
    case partial
}

/// Why a request failed.
public enum Failure: Sendable, Equatable {
    /// Not a request the daemon knows (`detail` says why).
    case badRequest(detail: String)
    case unknownStrategy(String)
    case invalidSettings([SettingsProblem])
    /// The daemon could not do it (`detail` says why).
    case failed(detail: String)
}

/// One invalid settings entry: the list (`field`), the entry's position in
/// it (none for the port ranges), and why (`code`).
public struct SettingsProblem: Sendable, Equatable, Decodable {
    public var field: String
    public var index: Int?
    public var code: String

    public init(field: String, index: Int?, code: String) {
        self.field = field
        self.index = index
        self.code = code
    }
}

/// What finding found: what it did, how the sites answer without jink, and
/// with each strategy tried, out of `checks` checks each.
public struct Found: Sendable, Equatable {
    public var result: FindResult
    public var checks: Int
    public var without: Checks
    public var tried: [Tried]

    public init(result: FindResult, checks: Int, without: Checks, tried: [Tried]) {
        self.result = result
        self.checks = checks
        self.without = without
        self.tried = tried
    }
}

public enum FindResult: Sendable, Equatable {
    /// `strategy` got through best; it is saved and on.
    case kept(strategy: String)
    /// Every site answers without jink; desync is as it was.
    case nothingBlocked
    /// No strategy got through better than none; desync is as it was.
    case noneHelped
    /// No site could even be looked up or reached; desync is as it was.
    case noNetwork
}

/// One round of checks: each site over each TLS version.
public struct Checks: Sendable, Equatable, Decodable {
    public var passed: Int
    public var failed: [FailedCheck]

    public init(passed: Int, failed: [FailedCheck]) {
        self.passed = passed
        self.failed = failed
    }
}

public struct FailedCheck: Sendable, Equatable, Decodable {
    public var host: String
    public var tls: Tls
    public var outcome: Outcome

    public init(host: String, tls: Tls, outcome: Outcome) {
        self.host = host
        self.tls = tls
        self.outcome = outcome
    }
}

public enum Tls: String, Sendable, Equatable, Decodable {
    case v12 = "1.2"
    case v13 = "1.3"
}

/// How a failed check ended.
public enum Outcome: String, Sendable, Equatable, Decodable {
    /// The name does not resolve.
    case noAddress = "no_address"
    /// No address takes a connection.
    case unreachable
    /// The connection was cut (or garbled) during the handshake.
    case cut
    /// The certificate is not the site's (a block page, usually).
    case certificate
    /// Handshake done, but no HTTP reply.
    case noReply = "no_reply"
    case timedOut = "timed_out"
}

/// A strategy tried; with a `problem` when it never came online, so its
/// sites were not checked.
public struct Tried: Sendable, Equatable {
    public var strategy: String
    public var checks: Checks
    public var problem: Problem?

    public init(strategy: String, checks: Checks, problem: Problem?) {
        self.strategy = strategy
        self.checks = checks
        self.problem = problem
    }
}
