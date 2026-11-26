// swift-tools-version: 6.2
// The jink app's code, in layers that only import downward (SwiftPM refuses
// any other import): JinkProtocol (the control channel's messages) <-
// JinkClient (the connection to the daemon) <- JinkUI (state and views).
// The app target only starts JinkUI.

import PackageDescription

/// Every target: Swift 6 (complete concurrency checking), warnings are
/// errors, and dependencies are explicit.
let strict: [SwiftSetting] = [
    .treatAllWarnings(as: .error),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
]

let package = Package(
    name: "JinkKit",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "JinkProtocol", targets: ["JinkProtocol"]),
        .library(name: "JinkClient", targets: ["JinkClient"]),
        .library(name: "JinkUI", targets: ["JinkUI"]),
    ],
    targets: [
        .target(name: "JinkProtocol", swiftSettings: strict),
        .target(name: "JinkClient", dependencies: ["JinkProtocol"], swiftSettings: strict),
        .target(
            name: "JinkUI",
            dependencies: ["JinkClient", "JinkProtocol"],
            resources: [.process("Resources")],
            swiftSettings: strict
        ),
        .testTarget(
            name: "JinkUITests",
            dependencies: ["JinkUI", "JinkClient", "JinkProtocol"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "JinkClientTests",
            dependencies: ["JinkClient", "JinkProtocol"],
            swiftSettings: strict
        ),
        .testTarget(
            name: "JinkProtocolTests",
            dependencies: ["JinkProtocol"],
            swiftSettings: strict
        ),
    ],
    swiftLanguageModes: [.v6]
)
