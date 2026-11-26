// What the app sends: one `Request` per line. `contract/requests.jsonl` has
// an example of each, which the tests encode.

/// A request to the daemon.
public enum Request: Sendable, Equatable {
    /// Answered with `.status`.
    case status
    /// Answered with `.strategies`.
    case strategies
    /// Starts desync with `strategy` (an id), or the one used last; restarts
    /// if already on. Answered with `.done`.
    case start(strategy: String?)
    /// Answered with `.done`.
    case stop
    /// Answered with `.settings`.
    case settings
    /// Replaces the settings, all or nothing. Answered with `.done`, or
    /// `.error(.invalidSettings)` listing every invalid entry.
    case updateSettings(Settings)
    /// Answered with `.done`.
    case setStartAtBoot(Bool)
    /// Tries every strategy and keeps the best; progress and result come in
    /// the status. Answered with `.done` at once.
    case find
    /// Answered with `.done`.
    case cancelFind
    /// Turns the connection into a stream of `.status` (now and at every
    /// change) and `.notice`.
    case watch
}

/// The settings, as the daemon keeps them (entries as text; the daemon
/// checks them).
public struct Settings: Sendable, Equatable, Codable {
    /// Domains (a pasted link is accepted; the daemon keeps its domain).
    public var mySites: [String]
    /// Addresses or networks (`1.2.3.0/24`).
    public var myIps: [String]
    public var excludedSites: [String]
    public var excludedIps: [String]
    public var gaming: Gaming
    public var ipList: IpList

    public init(
        mySites: [String],
        myIps: [String],
        excludedSites: [String],
        excludedIps: [String],
        gaming: Gaming,
        ipList: IpList
    ) {
        self.mySites = mySites
        self.myIps = myIps
        self.excludedSites = excludedSites
        self.excludedIps = excludedIps
        self.gaming = gaming
        self.ipList = ipList
    }
}

/// Gaming mode: game traffic on these ports, to the IPs of the IP list and
/// `myIps` only.
public struct Gaming: Sendable, Equatable, Codable {
    public var mode: GamingMode
    /// `from-to`, or one port.
    public var tcpPorts: String
    public var udpPorts: String

    public init(mode: GamingMode, tcpPorts: String, udpPorts: String) {
        self.mode = mode
        self.tcpPorts = tcpPorts
        self.udpPorts = udpPorts
    }
}

public enum GamingMode: String, Sendable, Equatable, Codable, CaseIterable {
    case off, tcp, udp, both
}

public enum IpList: String, Sendable, Equatable, Codable, CaseIterable {
    case off
    case builtIn = "built_in"
    case all
}
