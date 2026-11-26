// The control protocol's contract (`contract/` at the repository root),
// from the app's side: it decodes every example message to what it means,
// and encodes every example request exactly. The daemon's tests check the
// same files from its side.

import Foundation
import JinkProtocol
import Testing

/// The repository's `contract/` folder.
private let contract = URL(filePath: #filePath)
    .deletingLastPathComponent()  // JinkProtocolTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // JinkKit
    .deletingLastPathComponent()  // macos
    .deletingLastPathComponent()  // apps
    .deletingLastPathComponent()
    .appending(path: "contract")

private func status(
    _ engine: Engine,
    _ strategy: String,
    startAtBoot: Bool = false,
    found: Found? = nil
) -> Message {
    .status(Status(engine: engine, strategy: strategy, startAtBoot: startAtBoot, version: "0.1.0", found: found))
}

private func failed(_ host: String, _ tls: Tls, _ outcome: Outcome) -> FailedCheck {
    FailedCheck(host: host, tls: tls, outcome: outcome)
}

private let settings = Settings(
    mySites: ["youtube.com"],
    myIps: ["203.0.113.0/24"],
    excludedSites: ["example.com"],
    excludedIps: ["198.51.100.7/32"],
    gaming: Gaming(mode: .both, tcpPorts: "1024-65535", udpPorts: "27015"),
    ipList: .builtIn
)

/// What each example message means, by file name.
private let messages: [String: Message] = [
    "status-online": status(.on(.online(uplink: "en0", ipv6: true)), "alt", startAtBoot: true),
    "status-checking": status(.on(.checking), "alt"),
    "status-offline": status(.on(.offline), "alt"),
    "status-bypassed": status(
        .on(.bypassed(Problem(code: "routes_taken", detail: "another app (a VPN?) has the default routes"))),
        "alt"
    ),
    "status-off": status(.off, "alt4"),
    "status-starting": status(.starting, "alt4"),
    "status-failed": status(.failed(Problem(code: "tun", detail: "cannot open a utun device")), "alt"),
    "status-finding": status(.finding(step: 3, of: 14, strategy: "alt2"), "alt"),
    "status-finding-without": status(.finding(step: 1, of: 14, strategy: nil), "alt"),
    "status-found-kept": status(
        .starting,
        "alt4",
        found: Found(
            result: .kept(strategy: "alt4"),
            checks: 16,
            without: Checks(
                passed: 14,
                failed: [
                    failed("i.ytimg.com", .v12, .cut),
                    failed("redirector.googlevideo.com", .v13, .timedOut),
                ]
            ),
            tried: [
                Tried(
                    strategy: "alt",
                    checks: Checks(passed: 15, failed: [failed("i.ytimg.com", .v12, .noReply)]),
                    problem: nil
                ),
                Tried(strategy: "alt4", checks: Checks(passed: 16, failed: []), problem: nil),
                Tried(
                    strategy: "alt2",
                    checks: Checks(passed: 0, failed: []),
                    problem: Problem(code: "not_online", detail: "not online within 10 s")
                ),
            ]
        )
    ),
    "status-found-other": status(
        .off,
        "alt",
        found: Found(
            result: .noneHelped,
            checks: 16,
            without: Checks(
                passed: 0,
                failed: [
                    failed("discord.com", .v12, .certificate),
                    failed("discord.com", .v13, .noAddress),
                    failed("youtu.be", .v12, .unreachable),
                ]
            ),
            tried: []
        )
    ),
    "strategies": .strategies([
        StrategyInfo(id: "general", name: "general", variantOf: nil, support: .partial),
        StrategyInfo(id: "alt", name: "ALT", variantOf: nil, support: .full),
        StrategyInfo(id: "alt6", name: "ALT6", variantOf: "general", support: .partial),
    ]),
    "settings": .settings(
        Settings(
            mySites: ["youtube.com"],
            myIps: ["203.0.113.0/24"],
            excludedSites: ["example.com"],
            excludedIps: ["198.51.100.7/32"],
            gaming: Gaming(mode: .udp, tcpPorts: "1024-65535", udpPorts: "27015"),
            ipList: .all
        )
    ),
    "done": .done,
    "notice": .notice(
        Problem(code: "no_handshake", detail: "no handshake seen (first seen with 203.0.113.9:443)")
    ),
    "error-bad-request": .error(.badRequest(detail: "unknown variant `reboot`")),
    "error-unknown-strategy": .error(.unknownStrategy("alt99")),
    "error-invalid-settings": .error(
        .invalidSettings([
            SettingsProblem(field: "my_sites", index: 2, code: "no_dot"),
            SettingsProblem(field: "gaming.udp_ports", index: nil, code: "invalid_ports"),
        ])
    ),
    "error-failed": .error(
        .failed(detail: "cannot save /Library/Application Support/jink/state.json: disk full")
    ),
]

/// The example requests, in the file's order.
private let requests: [Request] = [
    .status,
    .strategies,
    .start(strategy: nil),
    .start(strategy: "alt13"),
    .stop,
    .settings,
    .updateSettings(settings),
    .setStartAtBoot(true),
    .find,
    .cancelFind,
    .watch,
]

@Test func everyExampleMessageDecodesToWhatItMeans() throws {
    let files = try FileManager.default.contentsOfDirectory(
        at: contract.appending(path: "messages"),
        includingPropertiesForKeys: nil
    )
    let names = files.map { $0.deletingPathExtension().lastPathComponent }
    #expect(Set(names) == Set(messages.keys))
    for file in files {
        let name = file.deletingPathExtension().lastPathComponent
        let decoded = try Wire.message(Data(contentsOf: file))
        #expect(decoded == messages[name], "\(name).json")
    }
}

@Test func everyExampleRequestEncodesExactly() throws {
    let text = try String(contentsOf: contract.appending(path: "requests.jsonl"), encoding: .utf8)
    let lines = text.split(separator: "\n").map { Data($0.utf8) }
    #expect(lines.count == requests.count)
    for (request, line) in zip(requests, lines) {
        let encoded = try Wire.line(request)
        #expect(encoded.last == 0x0A)
        // Keys in order: the same request is always the same line.
        let keys = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        let text = String(decoding: encoded, as: UTF8.self)
        let positions = (keys?.keys.sorted() ?? []).compactMap { text.range(of: "\"\($0)\":")?.lowerBound }
        #expect(positions == positions.sorted(), "\(text)")
        #expect(try json(encoded) == json(line), "\(request)")
    }
}

@Test func unknownKindsAreRefused() {
    let lines = [
        #"{"type":"reboot"}"#,
        #"{"type":"status","status":{"engine":{"state":"sleeping"},"strategy":"alt","start_at_boot":false,"version":"0.1.0","found":null}}"#,
        #"{"type":"error","error":{"code":"teapot"}}"#,
    ]
    for line in lines {
        #expect(throws: DecodingError.self) { try Wire.message(Data(line.utf8)) }
    }
}

/// `data` as a JSON object, to compare regardless of key order.
private func json(_ data: Data) throws -> NSDictionary? {
    try JSONSerialization.jsonObject(with: data) as? NSDictionary
}
