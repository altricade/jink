// The panel under the menu-bar icon: the switch, what jink is doing, the
// strategy, finding one, and the way to settings.

import AppKit
import JinkProtocol
import SwiftUI

struct MenuView: View {
    let model: AppModel
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch model.connection {
            case .connecting:
                Text("Connecting to the background service…", bundle: .module)
                    .foregroundStyle(.secondary)
            case .noDaemon(let detail):
                NoServiceView(model: model, detail: detail)
            case .connected(let status):
                ConnectedView(model: model, status: status)
            }
            if let trouble = model.trouble {
                Banner(text: explain(trouble)) { model.dismissTrouble() }
            }
            Divider()
            HStack {
                Button {
                    openSettings()
                    NSApp.activate()
                } label: {
                    Text("Settings…", bundle: .module)
                }
                Spacer()
                Button {
                    NSApp.terminate(nil)
                } label: {
                    Text("Quit", bundle: .module)
                }
            }
        }
        .padding(14)
        .frame(width: 330)
    }
}

/// When the app reaches no daemon: offer to install the service.
private struct NoServiceView: View {
    let model: AppModel
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("jink's background service is not running.", bundle: .module)
                .font(.headline)
            Text("It needs to be installed once; macOS asks for an administrator password.", bundle: .module)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ServiceButton(model: model, title: Text("Install service", bundle: .module))
            if let error = model.serviceError {
                Text(explain(error)).font(.caption).foregroundStyle(.red)
            }
            DisclosureGroup {
                Text(detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            } label: {
                Text("Details", bundle: .module).font(.caption)
            }
        }
    }
}

/// Installs (or updates) the service, showing that it works on it.
struct ServiceButton: View {
    let model: AppModel
    let title: Text

    var body: some View {
        HStack {
            Button {
                Task { await model.installService() }
            } label: {
                title
            }
            .disabled(model.serviceWork != nil)
            if model.serviceWork != nil {
                ProgressView().controlSize(.small)
            }
        }
    }
}

private struct ConnectedView: View {
    let model: AppModel
    let status: Status

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: "jink").font(.headline)
                    StatusLine(model: model, engine: status.engine)
                }
                Spacer()
                Toggle(
                    isOn: Binding(
                        get: { model.isOn },
                        set: { on in Task { await model.setOn(on) } }
                    )
                ) {
                    Text("On", bundle: .module)
                }
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(model.isFinding)
            }
            if model.needsReinstall {
                VStack(alignment: .leading, spacing: 6) {
                    Text("The background service is from another version of jink.", bundle: .module)
                        .font(.callout)
                    ServiceButton(model: model, title: Text("Update service", bundle: .module))
                }
            }
            StrategyPicker(model: model, current: status.strategy)
                .disabled(model.isFinding)
            FinderView(model: model, status: status)
            if let notice = model.notice {
                Text(explain(notice)).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// What the engine does, in a few words.
private struct StatusLine: View {
    let model: AppModel
    let engine: Engine

    var body: some View {
        Group {
            switch engine {
            case .off: Text("Off", bundle: .module)
            case .starting: Text("Starting…", bundle: .module)
            case .on(.checking): Text("On, checking the network…", bundle: .module)
            case .on(.online(let uplink, _)): Text("On, via \(uplink)", bundle: .module)
            case .on(.offline): Text("On, waiting for a network", bundle: .module)
            case .on(.bypassed(let problem)): Text("On, but not working: \(explain(problem))", bundle: .module)
            case .failed(let problem): Text("Stopped: \(explain(problem))", bundle: .module)
            case .finding(_, _, nil): Text("Finding a strategy…", bundle: .module)
            case .finding(_, _, .some(let id)): Text("Finding a strategy: trying \(model.name(of: id))", bundle: .module)
            }
        }
        .font(.callout)
        .foregroundStyle(model.indicator == .trouble ? .red : .secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct StrategyPicker: View {
    let model: AppModel
    let current: String

    var body: some View {
        Picker(
            selection: Binding(
                get: { current },
                set: { id in Task { await model.choose(id) } }
            )
        ) {
            ForEach(model.groups) { group in
                Section {
                    row(group.main)
                    ForEach(group.variants) { variant in row(variant) }
                }
            }
        } label: {
            Text("Strategy", bundle: .module)
        }
    }

    private func row(_ strategy: StrategyInfo) -> some View {
        Group {
            switch strategy.support {
            case .full: Text(verbatim: strategy.name)
            case .partial: Text("\(strategy.name) (partly)", bundle: .module)
            }
        }
        .tag(strategy.id)
    }
}

/// Finding a strategy: the button, the progress, and what was found.
private struct FinderView: View {
    let model: AppModel
    let status: Status
    @State private var details = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if case .finding(let step, let of, _) = status.engine {
                HStack {
                    ProgressView(value: Double(step), total: Double(max(of, 1)))
                    Button {
                        Task { await model.cancelFind() }
                    } label: {
                        Text("Cancel", bundle: .module)
                    }
                }
                Text("Takes a minute or two. Sites may not open meanwhile.", bundle: .module)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Button {
                    Task { await model.find() }
                } label: {
                    Text("Find the best strategy", bundle: .module)
                }
            }
            if let found = status.found {
                Text(summary(found)).font(.callout).fixedSize(horizontal: false, vertical: true)
                DisclosureGroup(isExpanded: $details) {
                    FoundDetails(model: model, found: found)
                } label: {
                    Text("Details", bundle: .module).font(.caption)
                }
            }
        }
    }

    private func summary(_ found: Found) -> String {
        switch found.result {
        case .kept(let id):
            let passed = found.tried.first { $0.strategy == id }?.checks.passed ?? found.checks
            return String(
                localized: "Kept \(model.name(of: id)): \(passed) of \(found.checks) checks passed (\(found.without.passed) without jink).",
                bundle: .module
            )
        case .nothingBlocked:
            return String(localized: "Nothing is blocked here: every site works without jink.", bundle: .module)
        case .noneHelped:
            return String(localized: "No strategy did better than without jink.", bundle: .module)
        case .noNetwork:
            return String(localized: "No network: the sites could not be reached at all.", bundle: .module)
        }
    }
}

private struct FoundDetails: View {
    let model: AppModel
    let found: Found

    var body: some View {
        Grid(alignment: .leading, verticalSpacing: 2) {
            row(Text("Without jink", bundle: .module), checks: found.without, problem: nil)
            ForEach(found.tried, id: \.strategy) { tried in
                row(Text(verbatim: model.name(of: tried.strategy)), checks: tried.checks, problem: tried.problem)
            }
        }
        .font(.caption)
    }

    private func row(_ name: Text, checks: Checks, problem: Problem?) -> some View {
        GridRow {
            name
            if let problem {
                Text(explain(problem)).foregroundStyle(.secondary)
            } else {
                Text(verbatim: "\(checks.passed)/\(found.checks)")
                    .help(checks.failed.map { "\($0.host) TLS \($0.tls.rawValue): \(explain($0.outcome))" }.joined(separator: "\n"))
            }
        }
    }
}

/// A message to dismiss.
private struct Banner: View {
    let text: String
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button(action: dismiss) { Image(systemName: "xmark") }
                .buttonStyle(.borderless)
        }
    }
}

extension AppModel {
    /// The name of the strategy `id` (the id if unknown).
    func name(of id: String) -> String {
        strategies.first { $0.id == id }?.name ?? id
    }
}
