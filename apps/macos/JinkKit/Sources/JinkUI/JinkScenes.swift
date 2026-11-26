// The app's scenes: the menu-bar item and the settings window. The app
// target only shows these, with `AppModel.live()`.

import AppKit
public import Foundation
import JinkClient
public import SwiftUI

public struct JinkScenes: Scene {
    @State private var model: AppModel

    public init(model: AppModel) {
        _model = State(initialValue: model)
    }

    public var body: some Scene {
        MenuBarExtra {
            MenuView(model: model)
        } label: {
            Image(model.indicator.asset, bundle: .module)
                .accessibilityLabel(Text(verbatim: "jink"))
                // The icon is there from launch: the model follows the
                // daemon from then until the app quits.
                .task { await model.run() }
        }
        .menuBarExtraStyle(.window)
        SwiftUI.Settings {
            SettingsView(model: model)
        }
    }
}

extension Indicator {
    /// The menu-bar image (a template: macOS tints it for the menu bar),
    /// made from `assets/brand/menubar-*.svg` by `assets/brand/export.sh`.
    var asset: String {
        switch self {
        case .off: "menubar-off"
        case .busy: "menubar-busy"
        case .on: "menubar-on"
        case .trouble: "menubar-trouble"
        }
    }

    /// The menu-bar image itself.
    var image: NSImage? {
        Bundle.module.image(forResource: asset)
    }
}

extension AppModel {
    /// Where the app keeps the `jink` command, inside its bundle.
    public static let command = "Contents/Helpers/jink"
    /// The Info.plist key with the bundled command's version.
    public static let versionKey = "JinkServiceVersion"

    /// The model for the app in `bundle`: the daemon's socket, and the
    /// service the bundle carries.
    public static func live(bundle: Bundle = .main) -> AppModel {
        let command = bundle.bundleURL.appending(path: command)
        return AppModel(
            daemon: DaemonClient(),
            service: BundledService(
                command: FileManager.default.isExecutableFile(atPath: command.path) ? command : nil
            ),
            bundledVersion: bundle.object(forInfoDictionaryKey: versionKey) as? String ?? ""
        )
    }
}
