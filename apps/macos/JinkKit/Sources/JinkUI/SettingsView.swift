// The settings window: own and excluded sites and IPs, gaming mode, the IP
// list, and the service. Edits are a draft until saved; the daemon checks
// them, and says which entries are not valid.

import JinkProtocol
import SwiftUI

/// The settings as edited: each list as text, one entry per line.
struct Draft: Equatable {
    var mySites: String
    var myIps: String
    var excludedSites: String
    var excludedIps: String
    var gaming: Gaming
    var ipList: IpList

    init(_ settings: JinkProtocol.Settings) {
        mySites = settings.mySites.joined(separator: "\n")
        myIps = settings.myIps.joined(separator: "\n")
        excludedSites = settings.excludedSites.joined(separator: "\n")
        excludedIps = settings.excludedIps.joined(separator: "\n")
        gaming = settings.gaming
        ipList = settings.ipList
    }

    /// The settings to send: blank lines and spaces around entries dropped.
    var settings: JinkProtocol.Settings {
        JinkProtocol.Settings(
            mySites: entries(mySites),
            myIps: entries(myIps),
            excludedSites: entries(excludedSites),
            excludedIps: entries(excludedIps),
            gaming: gaming,
            ipList: ipList
        )
    }

    /// Gaming mode in one switch: on covers both protocols and turns on the
    /// built-in IP list (game servers are matched by IP).
    var gamingOn: Bool {
        get { gaming.mode != .off }
        set {
            gaming.mode = newValue ? .both : .off
            if newValue && ipList == .off {
                ipList = .builtIn
            }
        }
    }
}

private func entries(_ text: String) -> [String] {
    text.split(whereSeparator: \.isNewline)
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
}

struct SettingsView: View {
    let model: AppModel

    var body: some View {
        Group {
            if let settings = model.settings {
                SettingsForm(model: model, saved: settings)
            } else {
                Text("Settings show once the background service runs.", bundle: .module)
                    .foregroundStyle(.secondary)
                    .padding(40)
            }
        }
        .frame(width: 520)
    }
}

private struct SettingsForm: View {
    let model: AppModel
    let saved: JinkProtocol.Settings
    @State private var draft: Draft
    @State private var problems: [SettingsProblem] = []
    @State private var saving = false

    init(model: AppModel, saved: JinkProtocol.Settings) {
        self.model = model
        self.saved = saved
        _draft = State(initialValue: Draft(saved))
    }

    var body: some View {
        VStack(spacing: 0) {
            TabView {
                general.tabItem { tab(Text("General", bundle: .module), icon: "gearshape") }
                sites.tabItem { tab(Text("Sites", bundle: .module), icon: "globe") }
                ips.tabItem { tab(Text("IPs", bundle: .module), icon: "network") }
                gaming.tabItem { tab(Text("Gaming", bundle: .module), icon: "gamecontroller") }
            }
            .padding([.top, .horizontal])
            HStack {
                if !problems.isEmpty {
                    Text("Some entries are not valid; nothing was saved.", bundle: .module)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button {
                    draft = Draft(saved)
                    problems = []
                } label: {
                    Text("Revert", bundle: .module)
                }
                .disabled(draft == Draft(saved))
                Button {
                    saving = true
                    Task {
                        problems = await model.save(draft.settings)
                        if problems.isEmpty, let settings = model.settings {
                            // Normalized by the daemon (links become domains).
                            draft = Draft(settings)
                        }
                        saving = false
                    }
                } label: {
                    Text("Save", bundle: .module)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving || draft.settings == saved)
            }
            .padding()
        }
    }

    /// A tab's title with its icon (the settings toolbar shows both).
    private func tab(_ title: Text, icon: String) -> some View {
        Label {
            title
        } icon: {
            Image(systemName: icon)
        }
    }

    private var general: some View {
        Form {
            Toggle(
                isOn: Binding(
                    get: { model.status?.startAtBoot ?? false },
                    set: { on in Task { await model.setStartAtBoot(on) } }
                )
            ) {
                Text("Turn on when the Mac starts", bundle: .module)
            }
            Picker(selection: $draft.ipList) {
                Text("Off", bundle: .module).tag(IpList.off)
                Text("Built-in list", bundle: .module).tag(IpList.builtIn)
                Text("All addresses", bundle: .module).tag(IpList.all)
            } label: {
                Text("IP list", bundle: .module)
                Text("Also treat traffic to these addresses, whatever the site name.", bundle: .module)
            }
            Section {
                ServiceButton(model: model, title: Text("Reinstall service", bundle: .module))
                Button(role: .destructive) {
                    Task { await model.uninstallService() }
                } label: {
                    Text("Remove service", bundle: .module)
                }
                .disabled(model.serviceWork != nil)
                if let error = model.serviceError {
                    Text(explain(error)).font(.caption).foregroundStyle(.red)
                }
            } header: {
                Text("Background service", bundle: .module)
            }
        }
        .formStyle(.grouped)
    }

    private var sites: some View {
        Form {
            ListField(
                title: Text("My sites", bundle: .module),
                hint: Text("Sites jink should also unblock: one per line; links are fine.", bundle: .module),
                text: $draft.mySites,
                problems: problems(in: "my_sites", entries: draft.settings.mySites)
            )
            ListField(
                title: Text("Excluded sites", bundle: .module),
                hint: Text("Sites jink should leave alone.", bundle: .module),
                text: $draft.excludedSites,
                problems: problems(in: "excluded_sites", entries: draft.settings.excludedSites)
            )
        }
        .formStyle(.grouped)
    }

    private var ips: some View {
        Form {
            ListField(
                title: Text("My IPs", bundle: .module),
                hint: Text("Addresses or networks (1.2.3.0/24) jink should also unblock.", bundle: .module),
                text: $draft.myIps,
                problems: problems(in: "my_ips", entries: draft.settings.myIps)
            )
            ListField(
                title: Text("Excluded IPs", bundle: .module),
                hint: Text("Addresses or networks jink should leave alone.", bundle: .module),
                text: $draft.excludedIps,
                problems: problems(in: "excluded_ips", entries: draft.settings.excludedIps)
            )
        }
        .formStyle(.grouped)
    }

    private var gaming: some View {
        Form {
            Toggle(isOn: $draft.gamingOn) {
                Text("Gaming mode", bundle: .module)
                Text("Also unblock game traffic to the servers of the IP list.", bundle: .module)
            }
            Section {
                Picker(selection: $draft.gaming.mode) {
                    Text("Off", bundle: .module).tag(GamingMode.off)
                    Text(verbatim: "TCP").tag(GamingMode.tcp)
                    Text(verbatim: "UDP").tag(GamingMode.udp)
                    Text("TCP and UDP", bundle: .module).tag(GamingMode.both)
                } label: {
                    Text("Protocols", bundle: .module)
                }
                TextField(text: $draft.gaming.tcpPorts) { Text("TCP ports", bundle: .module) }
                problemLines(problems(in: "gaming.tcp_ports", entries: [draft.gaming.tcpPorts]))
                TextField(text: $draft.gaming.udpPorts) { Text("UDP ports", bundle: .module) }
                problemLines(problems(in: "gaming.udp_ports", entries: [draft.gaming.udpPorts]))
            } header: {
                Text("Advanced", bundle: .module)
            }
        }
        .formStyle(.grouped)
    }

    /// The problems in `field`, with the entry each is about.
    private func problems(in field: String, entries: [String]) -> [String] {
        problems
            .filter { $0.field == field }
            .map { problem in
                let entry = problem.index.flatMap { entries.indices.contains($0) ? entries[$0] : nil } ?? entries.first ?? ""
                return "\(entry): \(explain(problem))"
            }
    }

    private func problemLines(_ lines: [String]) -> some View {
        ForEach(lines, id: \.self) { line in
            Text(verbatim: line).font(.caption).foregroundStyle(.red)
        }
    }
}

/// A list edited as text, with its invalid entries under it.
private struct ListField: View {
    let title: Text
    let hint: Text
    @Binding var text: String
    let problems: [String]

    var body: some View {
        Section {
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(minHeight: 90)
            ForEach(problems, id: \.self) { problem in
                Text(verbatim: problem).font(.caption).foregroundStyle(.red)
            }
        } header: {
            title
        } footer: {
            hint.font(.caption).foregroundStyle(.secondary)
        }
    }
}
