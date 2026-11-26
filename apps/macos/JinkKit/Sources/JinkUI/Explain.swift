// What the daemon's codes mean, in the app's language. A code this app does
// not know shows the daemon's own (English) text instead.

import Foundation
import JinkClient
import JinkProtocol

/// A sentence for `problem`.
func explain(_ problem: Problem) -> String {
    switch problem.code {
    case "routes_taken":
        String(localized: "Another app (a VPN?) routes all traffic, so jink stands aside.", bundle: .module)
    case "offline":
        String(localized: "There is no network.", bundle: .module)
    case "not_online":
        String(localized: "It did not get online in time.", bundle: .module)
    case "not_root":
        String(localized: "The service does not run as administrator.", bundle: .module)
    case "already_running":
        String(localized: "Another copy of jink is running.", bundle: .module)
    case "tun":
        String(localized: "jink could not create its network interface.", bundle: .module)
    case "route_table", "routes", "route_listener":
        String(localized: "jink could not read or change the network routes.", bundle: .module)
    case "capture", "raw_socket", "capture_ended":
        String(localized: "jink could not see or send network traffic.", bundle: .module)
    case "strategy":
        String(localized: "This strategy does not work with these settings.", bundle: .module)
    case "save":
        String(localized: "jink could not save its settings.", bundle: .module)
    case "no_handshake", "plan_failed", "fake_not_sent":
        String(localized: "Some connections went through unchanged.", bundle: .module)
    case "routes_left", "cleanup":
        String(localized: "jink could not remove all of its network routes.", bundle: .module)
    case "ended", "engine_task", "runtime", "stack", "lock", "state_file", "entropy":
        String(localized: "jink stopped unexpectedly.", bundle: .module)
    default:
        problem.detail
    }
}

/// A sentence for a failed site check.
func explain(_ outcome: Outcome) -> String {
    switch outcome {
    case .noAddress: String(localized: "name not found", bundle: .module)
    case .unreachable: String(localized: "unreachable", bundle: .module)
    case .cut: String(localized: "connection cut", bundle: .module)
    case .certificate: String(localized: "wrong certificate (a block page?)", bundle: .module)
    case .noReply: String(localized: "no reply", bundle: .module)
    case .timedOut: String(localized: "timed out", bundle: .module)
    }
}

/// A sentence for a failed request.
func explain(_ trouble: Trouble) -> String {
    switch trouble {
    case .client(.noDaemon), .client(.closed):
        String(localized: "The background service did not answer.", bundle: .module)
    case .client(.garbled), .client(.tooLong), .unexpected:
        String(localized: "The background service answered something this app does not understand. Update the service.", bundle: .module)
    case .client(.pathTooLong), .client(.cancelled):
        String(localized: "The request did not reach the background service.", bundle: .module)
    case .refused(.unknownStrategy(let id)):
        String(localized: "The service does not know the strategy \(id). Update the service.", bundle: .module)
    case .refused(.invalidSettings):
        String(localized: "Some settings are not valid.", bundle: .module)
    case .refused(.badRequest(let detail)), .refused(.failed(let detail)):
        detail
    }
}

/// A sentence for a failed install or removal of the service.
func explain(_ error: ServiceError) -> String {
    switch error {
    case .cancelled: ""
    case .missing: String(localized: "This copy of the app is damaged: download it again.", bundle: .module)
    case .failed(let detail): detail
    }
}

/// A sentence for an invalid settings entry.
func explain(_ problem: SettingsProblem) -> String {
    switch problem.code {
    case "empty": String(localized: "an empty line", bundle: .module)
    case "ip_address": String(localized: "an IP address: put it under IPs", bundle: .module)
    case "not_ascii": String(localized: "a non-Latin name: enter its xn-- form", bundle: .module)
    case "no_dot": String(localized: "the ending is missing (youtube.com, not youtube)", bundle: .module)
    case "invalid_site": String(localized: "not a site name", bundle: .module)
    case "invalid_ip": String(localized: "not an IP address or network", bundle: .module)
    case "invalid_ports": String(localized: "not a port or range (like 1024-65535)", bundle: .module)
    default: problem.code
    }
}
