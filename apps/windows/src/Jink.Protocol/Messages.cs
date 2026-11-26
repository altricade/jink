// What the daemon sends: one Message per line. Mirrors
// crates/jink-daemon/src/protocol.rs; contract/messages has an example of
// each, which the tests decode. Each closed family (Message, Engine, ...)
// is an abstract record whose cases are nested sealed records, so a value
// is always exactly one known case.

namespace Jink.Protocol;

/// <summary>A message from the daemon: the answer to one request, or an
/// update on a watching connection.</summary>
public abstract record Message
{
    private Message()
    {
    }

    /// <summary>The status (the answer to <c>status</c>, and every update
    /// while watching).</summary>
    public sealed record StatusReply(Status Status) : Message;

    /// <summary>The built-in strategies.</summary>
    public sealed record StrategiesReply(Items<StrategyInfo> Strategies) : Message;

    /// <summary>The settings.</summary>
    public sealed record SettingsReply(Settings Settings) : Message;

    /// <summary>The request was done.</summary>
    public sealed record Done : Message;

    /// <summary>The request failed.</summary>
    public sealed record Error(Failure Failure) : Message;

    /// <summary>Something went wrong without changing the state (each kind
    /// once per start).</summary>
    public sealed record Notice(Problem Problem) : Message;
}

/// <summary>Whether desync runs, with what, and what the last finding
/// found.</summary>
/// <param name="Engine">Whether desync runs.</param>
/// <param name="Strategy">The strategy desync runs (or last ran) with.</param>
/// <param name="StartAtBoot">Whether desync starts with the computer.</param>
/// <param name="Version">The daemon's version.</param>
/// <param name="Found">What the last finding found (since the daemon
/// started).</param>
public sealed record Status(Engine Engine, string Strategy, bool StartAtBoot, string Version, Found? Found);

/// <summary>Whether desync runs.</summary>
public abstract record Engine
{
    private Engine()
    {
    }

    /// <summary>Desync is off.</summary>
    public sealed record Off : Engine;

    /// <summary>Desync is starting.</summary>
    public sealed record Starting : Engine;

    /// <summary>Desync is on, on this network.</summary>
    public sealed record On(Network Network) : Engine;

    /// <summary>It stopped by itself or could not start.</summary>
    public sealed record Failed(Problem Problem) : Engine;

    /// <summary>Finding a strategy: at <paramref name="Step"/> of
    /// <paramref name="Of"/>, trying <paramref name="Strategy"/> (none at
    /// the first step, which checks the sites without jink).</summary>
    public sealed record Finding(int Step, int Of, string? Strategy) : Engine;
}

/// <summary>The network while desync is on.</summary>
public abstract record Network
{
    private Network()
    {
    }

    /// <summary>Just started.</summary>
    public sealed record Checking : Network;

    /// <summary>Traffic goes through jink and leaves through
    /// <paramref name="Uplink"/> (macOS).</summary>
    public sealed record Online(string Uplink, bool Ipv6) : Network;

    /// <summary>Traffic on every network goes through jink (Windows).</summary>
    public sealed record Active : Network;

    /// <summary>No network; jink waits for one.</summary>
    public sealed record Offline : Network;

    /// <summary>jink cannot work on this network, so traffic goes around
    /// it.</summary>
    public sealed record Bypassed(Problem Problem) : Network;
}

/// <summary>A problem: a stable <paramref name="Code"/> that the app explains
/// in its language, and the system's own (English) text as
/// <paramref name="Detail"/>.</summary>
public sealed record Problem(string Code, string Detail);

/// <summary>A built-in strategy.</summary>
/// <param name="Id">What requests name it by.</param>
/// <param name="Name">What people call it.</param>
/// <param name="VariantOf">The main strategy this one is a variant of.</param>
/// <param name="Support">How much of it this computer can run.</param>
public sealed record StrategyInfo(string Id, string Name, string? VariantOf, Support Support);

/// <summary>How much of a strategy this computer can run.</summary>
public enum Support
{
    /// <summary>All of it.</summary>
    Full,

    /// <summary>Some of its rules pass traffic unchanged here.</summary>
    Partial,
}

/// <summary>Why a request failed.</summary>
public abstract record Failure
{
    private Failure()
    {
    }

    /// <summary>Not a request the daemon knows.</summary>
    public sealed record BadRequest(string Detail) : Failure;

    /// <summary>No strategy has that id.</summary>
    public sealed record UnknownStrategy(string Strategy) : Failure;

    /// <summary>Some settings entries are invalid; nothing changed.</summary>
    public sealed record InvalidSettings(Items<SettingsProblem> Problems) : Failure;

    /// <summary>The daemon could not do it.</summary>
    public sealed record Failed(string Detail) : Failure;
}

/// <summary>One invalid settings entry: the list (<paramref name="Field"/>),
/// the entry's position in it (none for the port ranges), and why
/// (<paramref name="Code"/>).</summary>
public sealed record SettingsProblem(string Field, int? Index, string Code);

/// <summary>What finding found: what it did, how the sites answer without
/// jink, and with each strategy tried, out of <paramref name="Checks"/>
/// checks each.</summary>
public sealed record Found(FindResult Result, int Checks, Checks Without, Items<Tried> Tried);

/// <summary>What finding did.</summary>
public abstract record FindResult
{
    private FindResult()
    {
    }

    /// <summary><paramref name="Strategy"/> got through best; it is saved and
    /// on.</summary>
    public sealed record Kept(string Strategy) : FindResult;

    /// <summary>Every site answers without jink; desync is as it was.</summary>
    public sealed record NothingBlocked : FindResult;

    /// <summary>No strategy got through better than none; desync is as it
    /// was.</summary>
    public sealed record NoneHelped : FindResult;

    /// <summary>No site could even be looked up or reached; desync is as it
    /// was.</summary>
    public sealed record NoNetwork : FindResult;
}

/// <summary>One round of checks: each site over each TLS version.</summary>
public sealed record Checks(int Passed, Items<FailedCheck> Failed);

/// <summary>A check that failed.</summary>
public sealed record FailedCheck(string Host, Tls Tls, Outcome Outcome);

/// <summary>A TLS version.</summary>
public enum Tls
{
    /// <summary>TLS 1.2.</summary>
    V12,

    /// <summary>TLS 1.3.</summary>
    V13,
}

/// <summary>How a failed check ended.</summary>
public enum Outcome
{
    /// <summary>The name does not resolve.</summary>
    NoAddress,

    /// <summary>No address takes a connection.</summary>
    Unreachable,

    /// <summary>The connection was cut (or garbled) during the
    /// handshake.</summary>
    Cut,

    /// <summary>The certificate is not the site's (a block page,
    /// usually).</summary>
    Certificate,

    /// <summary>Handshake done, but no HTTP reply.</summary>
    NoReply,

    /// <summary>No answer within 5 seconds.</summary>
    TimedOut,
}

/// <summary>A strategy tried; with a <paramref name="Problem"/> when it never
/// came online, so its sites were not checked.</summary>
public sealed record Tried(string Strategy, Checks Checks, Problem? Problem);
