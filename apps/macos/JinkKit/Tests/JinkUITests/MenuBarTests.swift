// The menu-bar icons: one per state, each a template image (macOS tints
// it to suit a light or dark menu bar).

import AppKit
@testable import JinkUI
import Testing

@Test(arguments: [Indicator.off, .busy, .on, .trouble])
func everyStateHasATemplateIcon(_ indicator: Indicator) throws {
    let image = try #require(indicator.image, "\(indicator.asset)")
    #expect(image.isTemplate)
    #expect(image.size.width == 18 && image.size.height == 18)
}
