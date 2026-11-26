// What the windows say about the state, in the app's language: the status
// line, a strategy's name, and what finding found.

using Jink.Protocol;

namespace Jink.Core;

/// <summary>Sentences for the state.</summary>
public static class Describe
{
    /// <summary>What the engine does, in a few words; strategies named by
    /// <paramref name="nameOf"/>.</summary>
    public static string Engine(Engine engine, Func<string, string> nameOf)
    {
        ArgumentNullException.ThrowIfNull(nameOf);
        return engine switch
        {
            Protocol.Engine.Off => Strings.Off,
            Protocol.Engine.Starting => Strings.Starting,
            Protocol.Engine.On { Network: Network.Checking } => Strings.OnChecking,
            Protocol.Engine.On { Network: Network.Online online } => Strings.OnVia(online.Uplink),
            Protocol.Engine.On { Network: Network.Active } => Strings.On,
            Protocol.Engine.On { Network: Network.Offline } => Strings.OnWaiting,
            Protocol.Engine.On { Network: Network.Bypassed bypassed } =>
                Strings.OnNotWorking(Explain.Problem(bypassed.Problem)),
            Protocol.Engine.Failed failed => Strings.Stopped(Explain.Problem(failed.Problem)),
            Protocol.Engine.Finding { Strategy: { } id } => Strings.FindingTrying(nameOf(id)),
            Protocol.Engine.Finding => Strings.Finding,
            _ => engine.ToString(),
        };
    }

    /// <summary>A strategy as the picker shows it.</summary>
    public static string Strategy(StrategyInfo strategy)
    {
        ArgumentNullException.ThrowIfNull(strategy);
        return strategy.Support == Support.Full ? strategy.Name : Strings.Partly(strategy.Name);
    }

    /// <summary>What finding found, in a sentence.</summary>
    public static string Found(Found found, Func<string, string> nameOf)
    {
        ArgumentNullException.ThrowIfNull(found);
        ArgumentNullException.ThrowIfNull(nameOf);
        return found.Result switch
        {
            FindResult.Kept kept => Strings.Kept(
                nameOf(kept.Strategy),
                found.Tried.FirstOrDefault(t => t.Strategy == kept.Strategy)?.Checks.Passed ?? found.Checks,
                found.Checks,
                found.Without.Passed),
            FindResult.NothingBlocked => Strings.NothingBlocked,
            FindResult.NoneHelped => Strings.NoneHelped,
            FindResult.NoNetwork => Strings.NoNetwork,
            _ => found.Result.ToString(),
        };
    }

    /// <summary>One line of finding's details: how one round went (passed
    /// of all, or why it was not checked), and which checks failed.</summary>
    public static (string Result, string Failures) Round(Checks checks, int of, Problem? problem)
    {
        ArgumentNullException.ThrowIfNull(checks);
        var result = problem is null ? $"{checks.Passed}/{of}" : Explain.Problem(problem);
        var failures = string.Join(
            '\n',
            checks.Failed.Select(f => $"{f.Host} TLS {(f.Tls == Tls.V12 ? "1.2" : "1.3")}: {Explain.Outcome(f.Outcome)}"));
        return (result, failures);
    }
}
