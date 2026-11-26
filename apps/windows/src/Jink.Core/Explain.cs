// What the daemon's codes mean, in the app's language. A code this app does
// not know shows the daemon's own (English) text instead.

using Jink.Client;
using Jink.Protocol;

namespace Jink.Core;

/// <summary>Sentences for the daemon's codes.</summary>
public static class Explain
{
    /// <summary>A sentence for <paramref name="problem"/>.</summary>
    public static string Problem(Problem problem)
    {
        ArgumentNullException.ThrowIfNull(problem);
        return problem.Code switch
        {
            "routes_taken" => Strings.RoutesTaken,
            "offline" => Strings.NoNetworkNow,
            "not_online" => Strings.NotOnline,
            "not_root" or "access_denied" => Strings.NotAdministrator,
            "already_running" => Strings.AlreadyRunning,
            "tun" => Strings.NoInterface,
            "route_table" or "routes" or "route_listener" => Strings.Routes,
            "capture" or "raw_socket" or "capture_ended" => Strings.Capture,
            "missing_driver" => Strings.MissingDriver,
            "driver" => Strings.Driver,
            "tcp_timestamps" => Strings.TcpTimestamps,
            "strategy" or "filter" => Strings.BadStrategy,
            "save" => Strings.NotSavedService,
            "no_handshake" or "plan_failed" or "fake_not_sent" or "send_failed" => Strings.Unchanged,
            "routes_left" or "cleanup" => Strings.RoutesLeft,
            "ended" or "engine_task" or "runtime" or "stack" or "lock" or "state_file" or "entropy"
                or "crashed" => Strings.StoppedUnexpectedly,
            _ => problem.Detail,
        };
    }

    /// <summary>A few words for a failed site check.</summary>
    public static string Outcome(Outcome outcome) => outcome switch
    {
        Protocol.Outcome.NoAddress => Strings.NameNotFound,
        Protocol.Outcome.Unreachable => Strings.Unreachable,
        Protocol.Outcome.Cut => Strings.ConnectionCut,
        Protocol.Outcome.Certificate => Strings.WrongCertificate,
        Protocol.Outcome.NoReply => Strings.NoReply,
        Protocol.Outcome.TimedOut => Strings.TimedOut,
        _ => outcome.ToString(),
    };

    /// <summary>A sentence for a failed request.</summary>
    public static string Trouble(Trouble trouble) => trouble switch
    {
        Core.Trouble.NotAsked { Failure: ClientFailure.NoDaemon or ClientFailure.Closed } => Strings.NoAnswer,
        Core.Trouble.NotAsked or Core.Trouble.Unexpected => Strings.NotUnderstood,
        Core.Trouble.Refused { Failure: Failure.UnknownStrategy unknown } => Strings.UnknownStrategy(unknown.Strategy),
        Core.Trouble.Refused { Failure: Failure.InvalidSettings } => Strings.InvalidSettings,
        Core.Trouble.Refused { Failure: Failure.BadRequest bad } => bad.Detail,
        Core.Trouble.Refused { Failure: Failure.Failed failed } => failed.Detail,
        _ => trouble.ToString(),
    };

    /// <summary>A few words for an invalid settings entry.</summary>
    public static string Entry(SettingsProblem problem)
    {
        ArgumentNullException.ThrowIfNull(problem);
        return problem.Code switch
        {
            "empty" => Strings.EntryEmpty,
            "ip_address" => Strings.EntryIpAddress,
            "not_ascii" => Strings.EntryNotAscii,
            "no_dot" => Strings.EntryNoDot,
            "invalid_site" => Strings.EntryInvalidSite,
            "invalid_ip" => Strings.EntryInvalidIp,
            "invalid_ports" => Strings.EntryInvalidPorts,
            _ => problem.Code,
        };
    }
}
