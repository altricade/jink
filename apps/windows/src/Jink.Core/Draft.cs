// The settings as edited: each list as text, one entry per line. Edits are
// a draft until saved; the daemon checks them and says which entries are
// not valid.

using Jink.Protocol;

namespace Jink.Core;

/// <summary>The settings as the settings window edits them.</summary>
public sealed record Draft(
    string MySites,
    string MyIps,
    string ExcludedSites,
    string ExcludedIps,
    Gaming Gaming,
    IpList IpList)
{
    /// <summary>The draft of <paramref name="settings"/>.</summary>
    public static Draft Of(Settings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new(
            Lines(settings.MySites),
            Lines(settings.MyIps),
            Lines(settings.ExcludedSites),
            Lines(settings.ExcludedIps),
            settings.Gaming,
            settings.IpList);
    }

    /// <summary>Gaming mode in one switch: on covers both protocols.</summary>
    public bool GamingOn => Gaming.Mode != GamingMode.Off;

    /// <summary>The settings to send: blank lines and spaces around entries
    /// dropped.</summary>
    public Settings ToSettings() => new(
        Entries(MySites),
        Entries(MyIps),
        Entries(ExcludedSites),
        Entries(ExcludedIps),
        Gaming,
        IpList);

    /// <summary>This draft with gaming mode switched; switching it on covers
    /// both protocols and turns on the built-in IP list if none is on (game
    /// servers are matched by IP).</summary>
    public Draft WithGaming(bool on) => this with
    {
        Gaming = Gaming with { Mode = on ? GamingMode.Both : GamingMode.Off },
        IpList = on && IpList == IpList.Off ? IpList.BuiltIn : IpList,
    };

    private static string Lines(Items<string> entries) => string.Join('\n', entries);

    private static Items<string> Entries(string text) => new(
        text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
}
