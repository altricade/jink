// The jink app: a menu-bar item over the jink daemon. Everything is in the
// JinkKit package; this only starts it.

import JinkUI
import SwiftUI

@main
struct JinkApp: App {
    @State private var model = AppModel.live()

    var body: some Scene {
        JinkScenes(model: model)
    }
}
