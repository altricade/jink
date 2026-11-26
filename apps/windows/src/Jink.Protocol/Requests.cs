// What the app sends: one Request per line. contract/requests.jsonl has an
// example of each, which the tests encode.

namespace Jink.Protocol;

/// <summary>A request to the daemon.</summary>
public abstract record Request
{
    private Request()
    {
    }

    /// <summary>Answered with the status.</summary>
    public sealed record GetStatus : Request;

    /// <summary>Answered with the strategies.</summary>
    public sealed record GetStrategies : Request;

    /// <summary>Starts desync with <paramref name="Strategy"/> (an id), or the
    /// one used last; restarts if already on. Answered with done.</summary>
    public sealed record Start(string? Strategy) : Request;

    /// <summary>Answered with done.</summary>
    public sealed record Stop : Request;

    /// <summary>Answered with the settings.</summary>
    public sealed record GetSettings : Request;

    /// <summary>Replaces the settings, all or nothing. Answered with done,
    /// or an invalid-settings error listing every invalid entry.</summary>
    public sealed record UpdateSettings(Settings Settings) : Request;

    /// <summary>Answered with done.</summary>
    public sealed record SetStartAtBoot(bool On) : Request;

    /// <summary>Tries every strategy and keeps the best; progress and result
    /// come in the status. Answered with done at once.</summary>
    public sealed record Find : Request;

    /// <summary>Answered with done.</summary>
    public sealed record CancelFind : Request;

    /// <summary>Turns the connection into a stream of status (now and at
    /// every change) and notices.</summary>
    public sealed record Watch : Request;
}

/// <summary>The settings, as the daemon keeps them (entries as text; the
/// daemon checks them).</summary>
/// <param name="MySites">Domains (a pasted link is accepted; the daemon keeps
/// its domain).</param>
/// <param name="MyIps">Addresses or networks (<c>1.2.3.0/24</c>).</param>
/// <param name="ExcludedSites">Domains jink leaves alone.</param>
/// <param name="ExcludedIps">Addresses or networks jink leaves alone.</param>
/// <param name="Gaming">Gaming mode.</param>
/// <param name="IpList">Which IP list the IP rules use.</param>
public sealed record Settings(
    Items<string> MySites,
    Items<string> MyIps,
    Items<string> ExcludedSites,
    Items<string> ExcludedIps,
    Gaming Gaming,
    IpList IpList);

/// <summary>Gaming mode: game traffic on these ports, to the IPs of the IP
/// list and <c>MyIps</c> only.</summary>
/// <param name="Mode">Which protocols.</param>
/// <param name="TcpPorts"><c>from-to</c>, or one port.</param>
/// <param name="UdpPorts"><c>from-to</c>, or one port.</param>
public sealed record Gaming(GamingMode Mode, string TcpPorts, string UdpPorts);

/// <summary>Which game traffic gaming mode covers.</summary>
public enum GamingMode
{
    /// <summary>None.</summary>
    Off,

    /// <summary>TCP.</summary>
    Tcp,

    /// <summary>UDP.</summary>
    Udp,

    /// <summary>TCP and UDP.</summary>
    Both,
}

/// <summary>Which addresses the IP rules cover.</summary>
public enum IpList
{
    /// <summary>None: the IP rules are off.</summary>
    Off,

    /// <summary>The built-in list.</summary>
    BuiltIn,

    /// <summary>Every address.</summary>
    All,
}
