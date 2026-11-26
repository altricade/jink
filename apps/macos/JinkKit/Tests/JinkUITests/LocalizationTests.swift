// The String Catalog: every string has its Russian text, with the same
// placeholders as the English one.

import Foundation
import Testing

private let catalog = URL(filePath: #filePath)
    .deletingLastPathComponent()  // JinkUITests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // JinkKit
    .appending(path: "Sources/JinkUI/Resources/Localizable.xcstrings")

private struct Catalog: Decodable {
    struct Entry: Decodable {
        var localizations: [String: Localization]?
    }

    struct Localization: Decodable {
        var stringUnit: Unit
    }

    struct Unit: Decodable {
        var state: String
        var value: String
    }

    var strings: [String: Entry]
}

/// The placeholders in `text`, in order (`%@`, `%lld`, ...).
private func placeholders(_ text: String) -> [String] {
    text.matches(of: /%(lld|@|d|f)/).map { String($0.output.0) }
}

@Test func everyStringHasItsRussianText() throws {
    let strings = try JSONDecoder().decode(Catalog.self, from: Data(contentsOf: catalog)).strings
    #expect(!strings.isEmpty)
    for (key, entry) in strings {
        let russian = entry.localizations?["ru"]?.stringUnit
        #expect(russian?.state == "translated", "\(key)")
        #expect(russian.map { placeholders($0.value) } == placeholders(key), "\(key)")
    }
}
