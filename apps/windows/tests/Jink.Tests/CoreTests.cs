// The settings form, the app's text in both languages, and the layers.

using System.Globalization;
using System.Reflection;
using System.Resources;
using System.Text.RegularExpressions;
using Jink.Core;
using Jink.Protocol;

namespace Jink.Tests;

public sealed partial class CoreTests
{
    private static readonly Settings Saved = new(
        Items.Of("youtube.com", "discord.com"),
        Items.Of("203.0.113.0/24"),
        Items.Of<string>(),
        Items.Of<string>(),
        new Gaming(GamingMode.Off, "1024-65535", "1024-65535"),
        IpList.Off);

    [Fact]
    public void ListsAreEditedOnePerLine()
    {
        var draft = Draft.Of(Saved);
        Assert.Equal("youtube.com\ndiscord.com", draft.MySites);
        var edited = draft with { MySites = "  youtube.com \r\n\n x.com\n", ExcludedIps = " \n" };
        Assert.Equal(
            Saved with { MySites = Items.Of("youtube.com", "x.com") },
            edited.ToSettings());
        Assert.Equal(Saved, draft.ToSettings());
    }

    [Fact]
    public void TheGamingSwitchCoversBothProtocolsAndTheIpList()
    {
        var draft = Draft.Of(Saved);
        Assert.False(draft.GamingOn);
        var on = draft.WithGaming(true);
        Assert.True(on.GamingOn);
        Assert.Equal(GamingMode.Both, on.Gaming.Mode);
        Assert.Equal(IpList.BuiltIn, on.IpList);
        // An IP list already chosen stays.
        Assert.Equal(IpList.All, (draft with { IpList = IpList.All }).WithGaming(true).IpList);
        var off = on.WithGaming(false);
        Assert.Equal(GamingMode.Off, off.Gaming.Mode);
        Assert.Equal(IpList.BuiltIn, off.IpList);
    }

    [Fact]
    public void EveryTextHasItsRussianTextWithTheSamePlaceholders()
    {
        var english = Entries(CultureInfo.InvariantCulture);
        var russian = Entries(CultureInfo.GetCultureInfo("ru"));
        Assert.Equal(english.Keys.Order(StringComparer.Ordinal), russian.Keys.Order(StringComparer.Ordinal));
        foreach (var (key, text) in english)
        {
            Assert.Equal(Placeholders(text), Placeholders(russian[key]));
        }

        // Every text is read by a member of Strings, and every member's
        // text exists.
        var members = typeof(Strings).GetMembers(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m is PropertyInfo { PropertyType.Name: "String" } or MethodInfo { ReturnType.Name: "String" } && m.Name != nameof(Strings.Find))
            .Select(m => m.Name.StartsWith("get_", StringComparison.Ordinal) ? m.Name[4..] : m.Name)
            .ToHashSet();
        Assert.Equal(english.Keys.Order(StringComparer.Ordinal), members.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void TheTextFollowsTheChosenLanguage()
    {
        var before = Strings.Culture;
        try
        {
            Strings.Culture = CultureInfo.GetCultureInfo("ru");
            Assert.Equal("Включено, через en0", Strings.OnVia("en0"));
            Assert.Equal("Нет сети.", Explain.Problem(new Problem("offline", "no network")));
            Strings.Culture = CultureInfo.GetCultureInfo("en");
            Assert.Equal("On, via en0", Strings.OnVia("en0"));
            Assert.Equal("Kept ALT: 15 of 16 checks passed (4 without jink).", Strings.Kept("ALT", 15, 16, 4));
            // A code this app does not know shows the daemon's own text.
            Assert.Equal("a new thing", Explain.Problem(new Problem("new_code", "a new thing")));
            Assert.Equal("timed out", Explain.Outcome(Outcome.TimedOut));
            Assert.Equal("not a site name", Explain.Entry(new SettingsProblem("my_sites", 0, "invalid_site")));
        }
        finally
        {
            Strings.Culture = before;
        }
    }

    [Fact]
    public void LayersOnlyLookDown()
    {
        string[] Uses(Type type) =>
            [.. type.Assembly.GetReferencedAssemblies()
                .Select(a => a.Name ?? string.Empty)
                .Where(n => n.StartsWith("Jink.", StringComparison.Ordinal))
                .Order(StringComparer.Ordinal)];
        Assert.Empty(Uses(typeof(Wire)));
        Assert.Equal(["Jink.Protocol"], Uses(typeof(Client.DaemonClient)));
        Assert.Equal(["Jink.Client", "Jink.Protocol"], Uses(typeof(AppModel)));
        // Nothing below the app knows about windows.
        Assert.DoesNotContain(
            typeof(AppModel).Assembly.GetReferencedAssemblies(),
            a => a.Name?.StartsWith("Microsoft.UI", StringComparison.Ordinal) == true
                || a.Name?.StartsWith("Microsoft.WindowsAppSDK", StringComparison.Ordinal) == true);
    }

    private static Dictionary<string, string> Entries(CultureInfo culture)
    {
        var resources = new ResourceManager("Jink.Core.Resources.Strings", typeof(Strings).Assembly);
        using var set = resources.GetResourceSet(culture, createIfNotExists: true, tryParents: false)
            ?? throw new MissingManifestResourceException(culture.Name);
        return set.Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(e => (string)e.Key, e => (string)e.Value!);
    }

    private static string[] Placeholders(string text) =>
        [.. Placeholder().Matches(text).Select(m => m.Value).Order(StringComparer.Ordinal)];

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex Placeholder();
}
