// The settings as edited in the window.

import JinkProtocol
@testable import JinkUI
import Testing

private let saved = Settings(
    mySites: ["youtube.com", "discord.com"],
    myIps: [],
    excludedSites: [],
    excludedIps: ["10.0.0.0/8"],
    gaming: Gaming(mode: .off, tcpPorts: "1024-65535", udpPorts: "1024-65535"),
    ipList: .off
)

@Test func listsAreEditedOnePerLine() {
    var draft = Draft(saved)
    #expect(draft.mySites == "youtube.com\ndiscord.com")
    #expect(draft.settings == saved)
    draft.mySites = "  youtube.com \n\n discord.com\n\nrutracker.org  \n"
    #expect(draft.settings.mySites == ["youtube.com", "discord.com", "rutracker.org"])
}

@Test func theGamingSwitchCoversBothProtocolsAndTheIpList() {
    var draft = Draft(saved)
    #expect(!draft.gamingOn)
    draft.gamingOn = true
    #expect(draft.gaming.mode == .both)
    #expect(draft.ipList == .builtIn)
    draft.gamingOn = false
    #expect(draft.gaming.mode == .off)
    // The IP list stays as chosen; a chosen list is kept when turned on.
    #expect(draft.ipList == .builtIn)
    draft.ipList = .all
    draft.gamingOn = true
    #expect(draft.ipList == .all)
}
