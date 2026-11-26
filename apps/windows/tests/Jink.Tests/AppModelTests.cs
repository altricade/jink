// The app model against a fake daemon, run on a UI thread of its own as
// the app runs it.

using Jink.Client;
using Jink.Core;
using Jink.Protocol;

namespace Jink.Tests;

public sealed class AppModelTests : IAsyncDisposable
{
    private static readonly Settings Saved = new(
        Items.Of("youtube.com"),
        Items.Of<string>(),
        Items.Of<string>(),
        Items.Of<string>(),
        new Gaming(GamingMode.Off, "1024-65535", "1024-65535"),
        IpList.Off);

    private static readonly Items<StrategyInfo> Catalog = Items.Of(
        new StrategyInfo("general", "general", null, Support.Partial),
        new StrategyInfo("alt", "ALT", null, Support.Full),
        new StrategyInfo("alt6", "ALT6", "general", Support.Partial),
        new StrategyInfo("orphan", "ORPHAN", "gone", Support.Full));

    private readonly UiThread ui = new();
    private readonly FakeDaemon daemon = new();
    private readonly AppModel model;
    private readonly CancellationTokenSource running = new();
    private Task following = Task.CompletedTask;

    public AppModelTests()
    {
        daemon.Answer(Answer);
        model = new AppModel(daemon, "0.1.0", TimeSpan.FromMilliseconds(20));
    }

    /// <summary>Stops following, and waits for it, before the UI thread
    /// goes.</summary>
    public async ValueTask DisposeAsync()
    {
        await running.CancelAsync();
        await following;
        running.Dispose();
        ui.Dispose();
    }

    [Fact]
    public async Task ConnectingLoadsTheStrategiesAndSettings()
    {
        await Connect(new Engine.Off());
        Assert.True(await ui.Eventually(() => model.Settings == Saved));
        Assert.Equal(Catalog, await ui.Read(() => model.Strategies));
        Assert.Equal("ALT", await ui.Read(() => model.NameOf("alt")));
        Assert.Equal("nope", await ui.Read(() => model.NameOf("nope")));
        var groups = await ui.Read(() => model.Groups);
        Assert.Equal(["general", "alt", "orphan"], groups.Select(g => g.Main.Id));
        Assert.Equal(["alt6"], groups[0].Variants.Select(v => v.Id));
    }

    [Fact]
    public async Task WithoutTheDaemonItKeepsTrying()
    {
        daemon.Down = true;
        Run();
        Assert.True(await ui.Eventually(() => model.Connection is Connection.NoDaemon));
        Assert.True(await ui.Eventually(() => daemon.Watches >= 3));
        daemon.Down = false;
        Assert.True(await ui.Eventually(() => daemon.Watches >= 4));
        daemon.Push(StatusOf(new Engine.Off()));
        Assert.True(await ui.Eventually(() => model.Connection is Connection.Connected));
        // A daemon that goes away is followed again when it is back.
        daemon.HangUp();
        Assert.True(await ui.Eventually(() => model.Connection is Connection.NoDaemon));
        Assert.True(await ui.Eventually(() => daemon.Watches >= 5));
    }

    [Fact]
    public async Task TheIconAndSwitchFollowTheEngine()
    {
        await Connect(new Engine.Off());
        var problem = new Problem("x", "y");
        (Engine Engine, Indicator Indicator, bool On, bool Finding)[] cases =
        [
            (new Engine.Off(), Indicator.Off, false, false),
            (new Engine.Starting(), Indicator.Busy, true, false),
            (new Engine.On(new Network.Checking()), Indicator.Busy, true, false),
            (new Engine.On(new Network.Online("en0", false)), Indicator.On, true, false),
            (new Engine.On(new Network.Active()), Indicator.On, true, false),
            (new Engine.On(new Network.Offline()), Indicator.Trouble, true, false),
            (new Engine.On(new Network.Bypassed(problem)), Indicator.Trouble, true, false),
            (new Engine.Failed(problem), Indicator.Trouble, false, false),
            (new Engine.Finding(2, 14, "alt"), Indicator.Busy, false, true),
        ];
        foreach (var (engine, indicator, on, finding) in cases)
        {
            daemon.Push(StatusOf(engine));
            Assert.True(await ui.Eventually(() => model.Status?.Engine == engine), engine.ToString());
            Assert.Equal(indicator, await ui.Read(() => model.Indicator));
            Assert.Equal(on, await ui.Read(() => model.IsOn));
            Assert.Equal(finding, await ui.Read(() => model.IsFinding));
        }
    }

    [Fact]
    public async Task ChangesAreAnnouncedOnTheUiThread()
    {
        await Connect(new Engine.Off());
        var changes = new List<(string? Name, bool OnUi)>();
        await ui.Read(() =>
        {
            model.PropertyChanged += (_, e) =>
                changes.Add((e.PropertyName, SynchronizationContext.Current == ui));
            return true;
        });
        daemon.Push(StatusOf(new Engine.Starting()));
        Assert.True(await ui.Eventually(() => changes.Exists(c => c.Name == nameof(AppModel.Indicator))));
        var seen = await ui.Read(() => changes.ToList());
        Assert.All(seen, c => Assert.True(c.OnUi));
        Assert.Contains((nameof(AppModel.Connection), true), seen);
        Assert.Contains((nameof(AppModel.IsOn), true), seen);
    }

    [Fact]
    public async Task ADifferentServiceVersionAsksForAReinstall()
    {
        await Connect(new Engine.Off());
        Assert.False(await ui.Read(() => model.NeedsReinstall));
        daemon.Push(new Message.StatusReply(new Status(new Engine.Off(), "alt", false, "0.0.9", null)));
        Assert.True(await ui.Eventually(() => model.NeedsReinstall));
    }

    [Fact]
    public async Task ActionsSendTheirRequests()
    {
        await ui.Run(async () =>
        {
            await model.SetOnAsync(true);
            await model.SetOnAsync(false);
            await model.ChooseAsync("alt4");
            await model.FindAsync();
            await model.CancelFindAsync();
            await model.SetStartAtBootAsync(true);
        });
        Assert.Equal(
            [
                new Request.Start(null),
                new Request.Stop(),
                new Request.Start("alt4"),
                new Request.Find(),
                new Request.CancelFind(),
                new Request.SetStartAtBoot(true),
            ],
            daemon.Sent);
        Assert.Null(await ui.Read(() => model.Trouble));
    }

    [Fact]
    public async Task FailedRequestsAreShownUntilDismissed()
    {
        daemon.Answer(_ => new Message.Error(new Failure.UnknownStrategy("alt99")));
        await ui.Run(() => model.ChooseAsync("alt99"));
        var trouble = await ui.Read(() => model.Trouble);
        Assert.Equal(new Trouble.Refused(new Failure.UnknownStrategy("alt99")), trouble);
        Assert.Contains("alt99", Explain.Trouble(trouble!), StringComparison.Ordinal);
        await ui.Read(() =>
        {
            model.DismissTrouble();
            return true;
        });
        Assert.Null(await ui.Read(() => model.Trouble));

        daemon.Down = true;
        await ui.Run(() => model.FindAsync());
        Assert.Equal(new Trouble.NotAsked(ClientFailure.NoDaemon), await ui.Read(() => model.Trouble));

        daemon.Down = false;
        daemon.Answer(_ => new Message.SettingsReply(Saved));
        await ui.Run(() => model.FindAsync());
        Assert.Equal(new Trouble.Unexpected(), await ui.Read(() => model.Trouble));
    }

    [Fact]
    public async Task SettingsAreSavedOrTheirProblemsListed()
    {
        var invalid = Items.Of(new SettingsProblem("my_sites", 0, "no_dot"));
        var changed = Saved with { MySites = Items.Of("youtube") };
        daemon.Answer(request => request switch
        {
            Request.UpdateSettings { Settings.MySites: ["youtube"] } => new Message.Error(new Failure.InvalidSettings(invalid)),
            Request.UpdateSettings => new Message.Done(),
            Request.GetSettings => new Message.SettingsReply(Saved with { MySites = Items.Of("discord.com") }),
            _ => new Message.Done(),
        });
        Assert.Equal(invalid, await ui.Run(() => model.SaveAsync(changed)));
        Assert.Null(await ui.Read(() => model.Settings));
        Assert.Null(await ui.Read(() => model.Trouble));

        var problems = await ui.Run(() => model.SaveAsync(Saved with { MySites = Items.Of("https://discord.com/app") }));
        Assert.Empty(problems);
        // The daemon's normalized settings are kept.
        Assert.Equal(Items.Of("discord.com"), (await ui.Read(() => model.Settings))?.MySites);
    }

    private Message Answer(Request request) => request switch
    {
        Request.GetStrategies => new Message.StrategiesReply(Catalog),
        Request.GetSettings => new Message.SettingsReply(Saved),
        _ => new Message.Done(),
    };

    private static Message.StatusReply StatusOf(Engine engine) =>
        new(new Status(engine, "alt", false, "0.1.0", null));

    /// <summary>Starts following the daemon, on the UI thread.</summary>
    private void Run() => following = ui.Run(() => model.RunAsync(running.Token));

    private async Task Connect(Engine engine)
    {
        Run();
        Assert.True(await ui.Eventually(() => daemon.Watches == 1));
        daemon.Push(StatusOf(engine));
        Assert.True(await ui.Eventually(() => model.Status?.Engine == engine));
    }
}
