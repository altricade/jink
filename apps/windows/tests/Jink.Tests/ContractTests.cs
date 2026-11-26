// The control protocol's contract (contract/ at the repository root), from
// the Windows app's side: it decodes every example message to what it
// means, and encodes every example request exactly. The daemon's and the
// Mac app's tests check the same files.

using System.Text;
using Jink.Protocol;

namespace Jink.Tests;

public sealed class ContractTests
{
    private static readonly Settings Example = new(
        Items.Of("youtube.com"),
        Items.Of("203.0.113.0/24"),
        Items.Of("example.com"),
        Items.Of("198.51.100.7/32"),
        new Gaming(GamingMode.Both, "1024-65535", "27015"),
        IpList.BuiltIn);

    /// <summary>What each example message means, by file name.</summary>
    private static readonly Dictionary<string, Message> Messages = new()
    {
        ["status-online"] = Status(new Engine.On(new Network.Online("en0", true)), "alt", startAtBoot: true),
        ["status-checking"] = Status(new Engine.On(new Network.Checking()), "alt"),
        ["status-active"] = Status(new Engine.On(new Network.Active()), "alt"),
        ["status-offline"] = Status(new Engine.On(new Network.Offline()), "alt"),
        ["status-bypassed"] = Status(
            new Engine.On(new Network.Bypassed(new Problem("routes_taken", "another app (a VPN?) has the default routes"))),
            "alt"),
        ["status-off"] = Status(new Engine.Off(), "alt4"),
        ["status-starting"] = Status(new Engine.Starting(), "alt4"),
        ["status-failed"] = Status(new Engine.Failed(new Problem("tun", "cannot open a utun device")), "alt"),
        ["status-finding"] = Status(new Engine.Finding(3, 14, "alt2"), "alt"),
        ["status-finding-without"] = Status(new Engine.Finding(1, 14, null), "alt"),
        ["status-found-kept"] = Status(
            new Engine.Starting(),
            "alt4",
            found: new Found(
                new FindResult.Kept("alt4"),
                16,
                new Checks(14, Items.Of(
                    Failed("i.ytimg.com", Tls.V12, Outcome.Cut),
                    Failed("redirector.googlevideo.com", Tls.V13, Outcome.TimedOut))),
                Items.Of(
                    new Tried("alt", new Checks(15, Items.Of(Failed("i.ytimg.com", Tls.V12, Outcome.NoReply))), null),
                    new Tried("alt4", new Checks(16, Items.Of<FailedCheck>()), null),
                    new Tried(
                        "alt2",
                        new Checks(0, Items.Of<FailedCheck>()),
                        new Problem("not_online", "not online within 10 s"))))),
        ["status-found-other"] = Status(
            new Engine.Off(),
            "alt",
            found: new Found(
                new FindResult.NoneHelped(),
                16,
                new Checks(0, Items.Of(
                    Failed("discord.com", Tls.V12, Outcome.Certificate),
                    Failed("discord.com", Tls.V13, Outcome.NoAddress),
                    Failed("youtu.be", Tls.V12, Outcome.Unreachable))),
                Items.Of<Tried>())),
        ["strategies"] = new Message.StrategiesReply(Items.Of(
            new StrategyInfo("general", "general", null, Support.Partial),
            new StrategyInfo("alt", "ALT", null, Support.Full),
            new StrategyInfo("alt6", "ALT6", "general", Support.Partial))),
        ["settings"] = new Message.SettingsReply(Example with
        {
            Gaming = new Gaming(GamingMode.Udp, "1024-65535", "27015"),
            IpList = IpList.All,
        }),
        ["done"] = new Message.Done(),
        ["notice"] = new Message.Notice(
            new Problem("no_handshake", "no handshake seen (first seen with 203.0.113.9:443)")),
        ["error-bad-request"] = new Message.Error(new Failure.BadRequest("unknown variant `reboot`")),
        ["error-unknown-strategy"] = new Message.Error(new Failure.UnknownStrategy("alt99")),
        ["error-invalid-settings"] = new Message.Error(new Failure.InvalidSettings(Items.Of(
            new SettingsProblem("my_sites", 2, "no_dot"),
            new SettingsProblem("gaming.udp_ports", null, "invalid_ports")))),
        ["error-failed"] = new Message.Error(
            new Failure.Failed("cannot save /Library/Application Support/jink/state.json: disk full")),
    };

    /// <summary>The example requests, in the file's order.</summary>
    private static readonly Request[] Requests =
    [
        new Request.GetStatus(),
        new Request.GetStrategies(),
        new Request.Start(null),
        new Request.Start("alt13"),
        new Request.Stop(),
        new Request.GetSettings(),
        new Request.UpdateSettings(Example),
        new Request.SetStartAtBoot(true),
        new Request.Find(),
        new Request.CancelFind(),
        new Request.Watch(),
    ];

    [Fact]
    public void EveryExampleMessageDecodesToWhatItMeans()
    {
        var files = Directory.GetFiles(Path.Combine(Repository.Contract(), "messages"), "*.json");
        Assert.Equal(
            Messages.Keys.Order(StringComparer.Ordinal),
            files.Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal));
        foreach (var file in files)
        {
            var decoded = Wire.Decode(File.ReadAllBytes(file).AsSpan().TrimEnd((byte)'\n'));
            Assert.Equal(Messages[Path.GetFileNameWithoutExtension(file)!], decoded);
        }
    }

    [Fact]
    public void EveryExampleRequestEncodesExactly()
    {
        var lines = File.ReadAllLines(Path.Combine(Repository.Contract(), "requests.jsonl"));
        Assert.Equal(Requests.Select(r => Encoding.UTF8.GetString(Wire.Encode(r))), lines);
    }

    [Theory]
    [InlineData("""{"type":"reboot"}""")]
    [InlineData("""{"type":"status","status":{"engine":{"state":"sleeping"},"strategy":"alt","start_at_boot":false,"version":"0.1.0","found":null}}""")]
    [InlineData("""{"type":"error","error":{"code":"teapot"}}""")]
    [InlineData("""{"type":"status","status":{"engine":{"state":"off"}}}""")]
    [InlineData("""{"type":"done""")]
    [InlineData("""{"type":7}""")]
    [InlineData("""[]""")]
    public void UnknownOrBrokenMessagesAreRefused(string line) =>
        Assert.Throws<WireException>(() => Wire.Decode(Encoding.UTF8.GetBytes(line)));

    private static Message.StatusReply Status(Engine engine, string strategy, bool startAtBoot = false, Found? found = null) =>
        new(new Protocol.Status(engine, strategy, startAtBoot, "0.1.0", found));

    private static FailedCheck Failed(string host, Tls tls, Outcome outcome) => new(host, tls, outcome);
}
