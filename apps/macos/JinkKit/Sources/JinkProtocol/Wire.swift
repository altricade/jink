// The messages as JSON lines: field names in snake_case, the kind of each
// message or state in a tag field (`type`, `state`, `code`, `result`).

public import Foundation

/// Turns requests into lines and lines into messages.
public enum Wire {
    /// `request` as one line, ending in a newline.
    public static func line(_ request: Request) throws -> Data {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        // The same request is always the same line.
        encoder.outputFormatting = .sortedKeys
        var line = try encoder.encode(request)
        line.append(0x0A)
        return line
    }

    /// The message in `line` (with or without its newline).
    public static func message(_ line: Data) throws -> Message {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Message.self, from: line)
    }
}

extension Request: Encodable {
    private enum CodingKeys: String, CodingKey {
        case cmd, strategy, settings, on
    }

    public func encode(to encoder: any Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status: try fields.encode("status", forKey: .cmd)
        case .strategies: try fields.encode("strategies", forKey: .cmd)
        case .start(let strategy):
            try fields.encode("start", forKey: .cmd)
            try fields.encodeIfPresent(strategy, forKey: .strategy)
        case .stop: try fields.encode("stop", forKey: .cmd)
        case .settings: try fields.encode("settings", forKey: .cmd)
        case .updateSettings(let settings):
            try fields.encode("update_settings", forKey: .cmd)
            try fields.encode(settings, forKey: .settings)
        case .setStartAtBoot(let on):
            try fields.encode("set_start_at_boot", forKey: .cmd)
            try fields.encode(on, forKey: .on)
        case .find: try fields.encode("find", forKey: .cmd)
        case .cancelFind: try fields.encode("cancel_find", forKey: .cmd)
        case .watch: try fields.encode("watch", forKey: .cmd)
        }
    }
}

extension Message: Decodable {
    private enum CodingKeys: String, CodingKey {
        case type, status, strategies, settings, error, notice
    }

    private enum Kind: String, Decodable {
        case status, strategies, settings, done, error, notice
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Kind.self, forKey: .type) {
        case .status: self = .status(try fields.decode(Status.self, forKey: .status))
        case .strategies:
            self = .strategies(try fields.decode([StrategyInfo].self, forKey: .strategies))
        case .settings: self = .settings(try fields.decode(Settings.self, forKey: .settings))
        case .done: self = .done
        case .error: self = .error(try fields.decode(Failure.self, forKey: .error))
        case .notice: self = .notice(try fields.decode(Problem.self, forKey: .notice))
        }
    }
}

extension Engine: Decodable {
    private enum CodingKeys: String, CodingKey {
        case state, network, problem, step, of, strategy
    }

    private enum State: String, Decodable {
        case off, starting, on, failed, finding
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(State.self, forKey: .state) {
        case .off: self = .off
        case .starting: self = .starting
        case .on: self = .on(try fields.decode(Network.self, forKey: .network))
        case .failed: self = .failed(try fields.decode(Problem.self, forKey: .problem))
        case .finding:
            self = .finding(
                step: try fields.decode(Int.self, forKey: .step),
                of: try fields.decode(Int.self, forKey: .of),
                strategy: try fields.decodeIfPresent(String.self, forKey: .strategy)
            )
        }
    }
}

extension Network: Decodable {
    private enum CodingKeys: String, CodingKey {
        case state, uplink, ipv6, problem
    }

    private enum State: String, Decodable {
        case checking, online, active, offline, bypassed
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(State.self, forKey: .state) {
        case .checking: self = .checking
        case .online:
            self = .online(
                uplink: try fields.decode(String.self, forKey: .uplink),
                ipv6: try fields.decode(Bool.self, forKey: .ipv6)
            )
        case .active: self = .active
        case .offline: self = .offline
        case .bypassed: self = .bypassed(try fields.decode(Problem.self, forKey: .problem))
        }
    }
}

extension Failure: Decodable {
    private enum CodingKeys: String, CodingKey {
        case code, detail, strategy, problems
    }

    private enum Code: String, Decodable {
        case badRequest = "bad_request"
        case unknownStrategy = "unknown_strategy"
        case invalidSettings = "invalid_settings"
        case failed
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Code.self, forKey: .code) {
        case .badRequest: self = .badRequest(detail: try fields.decode(String.self, forKey: .detail))
        case .unknownStrategy:
            self = .unknownStrategy(try fields.decode(String.self, forKey: .strategy))
        case .invalidSettings:
            self = .invalidSettings(try fields.decode([SettingsProblem].self, forKey: .problems))
        case .failed: self = .failed(detail: try fields.decode(String.self, forKey: .detail))
        }
    }
}

extension Found: Decodable {
    private enum CodingKeys: String, CodingKey {
        case checks, without, tried
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        // `result` (and its `strategy`) sit beside the other fields.
        result = try FindResult(from: decoder)
        checks = try fields.decode(Int.self, forKey: .checks)
        without = try fields.decode(Checks.self, forKey: .without)
        tried = try fields.decode([Tried].self, forKey: .tried)
    }
}

extension FindResult: Decodable {
    private enum CodingKeys: String, CodingKey {
        case result, strategy
    }

    private enum Result: String, Decodable {
        case kept
        case nothingBlocked = "nothing_blocked"
        case noneHelped = "none_helped"
        case noNetwork = "no_network"
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(Result.self, forKey: .result) {
        case .kept: self = .kept(strategy: try fields.decode(String.self, forKey: .strategy))
        case .nothingBlocked: self = .nothingBlocked
        case .noneHelped: self = .noneHelped
        case .noNetwork: self = .noNetwork
        }
    }
}

extension Tried: Decodable {
    private enum CodingKeys: String, CodingKey {
        case strategy, problem
    }

    public init(from decoder: any Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        strategy = try fields.decode(String.self, forKey: .strategy)
        // `passed` and `failed` sit beside the other fields.
        checks = try Checks(from: decoder)
        problem = try fields.decodeIfPresent(Problem.self, forKey: .problem)
    }
}
