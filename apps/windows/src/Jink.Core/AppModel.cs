// The app's state: what the daemon says, kept current by watching it, and
// the actions the windows take. Windows only read this and call its
// methods. It lives on the UI thread: every await resumes there, and every
// change is announced there.

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Jink.Client;
using Jink.Protocol;

namespace Jink.Core;

/// <summary>Whether the app reaches the daemon.</summary>
public abstract record Connection
{
    private Connection()
    {
    }

    /// <summary>Not yet known.</summary>
    public sealed record Connecting : Connection;

    /// <summary>The service is not installed or not running;
    /// <paramref name="Detail"/> is the system's text.</summary>
    public sealed record NoDaemon(string Detail) : Connection;

    /// <summary>Connected, with the latest status.</summary>
    public sealed record Connected(Status Status) : Connection;
}

/// <summary>A main strategy and its variants, as the picker shows
/// them.</summary>
public sealed record StrategyGroup(StrategyInfo Main, Items<StrategyInfo> Variants);

/// <summary>What the tray icon shows.</summary>
public enum Indicator
{
    /// <summary>Desync is off (or the daemon is not there).</summary>
    Off,

    /// <summary>Starting, checking the network, or finding a
    /// strategy.</summary>
    Busy,

    /// <summary>On and working.</summary>
    On,

    /// <summary>On but not working (offline, bypassed), or failed.</summary>
    Trouble,
}

/// <summary>What the last request that failed said (the windows show it
/// once).</summary>
public abstract record Trouble
{
    private Trouble()
    {
    }

    /// <summary>The daemon could not be asked.</summary>
    public sealed record NotAsked(ClientFailure Failure) : Trouble;

    /// <summary>The daemon refused.</summary>
    public sealed record Refused(Failure Failure) : Trouble;

    /// <summary>The daemon answered with something that does not answer the
    /// request.</summary>
    public sealed record Unexpected : Trouble;
}

/// <summary>The app's state and actions.</summary>
/// <param name="daemon">What it talks to.</param>
/// <param name="version">The version of jink this app is (the daemon
/// should be the same).</param>
/// <param name="retry">How long to wait before connecting again while the
/// daemon is unreachable.</param>
public sealed class AppModel(IDaemonLink daemon, string version, TimeSpan retry) : INotifyPropertyChanged
{
    private Connection connection = new Connection.Connecting();
    private Items<StrategyInfo> strategies = Items.Of<StrategyInfo>();
    private Settings? settings;
    private Problem? notice;
    private Trouble? trouble;

    /// <inheritdoc/>
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Whether the app reaches the daemon.</summary>
    public Connection Connection
    {
        get => connection;
        private set => Set(ref connection, value, [nameof(Status), nameof(Indicator), nameof(IsOn), nameof(IsFinding), nameof(NeedsReinstall)]);
    }

    /// <summary>The strategies, in the daemon's order.</summary>
    public Items<StrategyInfo> Strategies
    {
        get => strategies;
        private set => Set(ref strategies, value, [nameof(Groups)]);
    }

    /// <summary>The settings, once loaded.</summary>
    public Settings? Settings
    {
        get => settings;
        private set => Set(ref settings, value, []);
    }

    /// <summary>The latest notice since the app connected.</summary>
    public Problem? Notice
    {
        get => notice;
        private set => Set(ref notice, value, []);
    }

    /// <summary>The latest failed request, until
    /// <see cref="DismissTrouble"/>.</summary>
    public Trouble? Trouble
    {
        get => trouble;
        private set => Set(ref trouble, value, []);
    }

    /// <summary>The version of jink this app is.</summary>
    public string Version { get; } = version;

    /// <summary>The status, if connected.</summary>
    public Status? Status => Connection is Connection.Connected connected ? connected.Status : null;

    /// <summary>What the tray icon shows.</summary>
    public Indicator Indicator => Status?.Engine switch
    {
        null or Engine.Off => Indicator.Off,
        Engine.Starting or Engine.Finding or Engine.On { Network: Network.Checking } => Indicator.Busy,
        Engine.On { Network: Network.Online or Network.Active } => Indicator.On,
        _ => Indicator.Trouble,
    };

    /// <summary>Whether desync is on or on its way (the switch's
    /// position).</summary>
    public bool IsOn => Status?.Engine is Engine.Starting or Engine.On;

    /// <summary>Whether a strategy is being found.</summary>
    public bool IsFinding => Status?.Engine is Engine.Finding;

    /// <summary>The running service is another version than this app (the
    /// installer puts both in place together; this means a broken
    /// install).</summary>
    public bool NeedsReinstall => Status is { } status && status.Version != Version;

    /// <summary>The strategies by main strategy, in the daemon's order; a
    /// variant whose main one is unknown stands alone.</summary>
    public Items<StrategyGroup> Groups
    {
        get
        {
            var mains = Strategies.Where(s => s.VariantOf is null).Select(s => s.Id).ToHashSet();
            return new(Strategies
                .Where(s => s.VariantOf is not { } main || !mains.Contains(main))
                .Select(main => new StrategyGroup(
                    main,
                    new(Strategies.Where(s => s.VariantOf == main.Id)))));
        }
    }

    /// <summary>The display name of the strategy <paramref name="id"/>.</summary>
    public string NameOf(string id) => Strategies.FirstOrDefault(s => s.Id == id)?.Name ?? id;

    /// <summary>Follows the daemon until cancelled: connects, keeps the state
    /// current, and reconnects when it goes away.</summary>
    public async Task RunAsync(CancellationToken cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            await FollowAsync(cancellation).ConfigureAwait(true);
            try
            {
                await Task.Delay(retry, cancellation).ConfigureAwait(true);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Turns desync on (with the strategy used last) or
    /// off.</summary>
    public Task SetOnAsync(bool on) => ActAsync(on ? new Request.Start(null) : new Request.Stop());

    /// <summary>Switches to <paramref name="strategy"/> (turning desync
    /// on).</summary>
    public Task ChooseAsync(string strategy) => ActAsync(new Request.Start(strategy));

    /// <summary>Finds the best strategy.</summary>
    public Task FindAsync() => ActAsync(new Request.Find());

    /// <summary>Stops finding, leaving desync as it was.</summary>
    public Task CancelFindAsync() => ActAsync(new Request.CancelFind());

    /// <summary>Whether desync turns on when Windows starts.</summary>
    public Task SetStartAtBootAsync(bool on) => ActAsync(new Request.SetStartAtBoot(on));

    /// <summary>Saves <paramref name="changed"/>; the invalid entries if any
    /// (then nothing changed).</summary>
    public async Task<Items<SettingsProblem>> SaveAsync(Settings changed)
    {
        switch (await SendAsync(new Request.UpdateSettings(changed)).ConfigureAwait(true))
        {
            case Message.Done:
                // Sent back normalized (links become domains).
                if (await AskAsync(new Request.GetSettings()).ConfigureAwait(true) is Message.SettingsReply saved)
                {
                    Settings = saved.Settings;
                }

                return Items.Of<SettingsProblem>();
            case Message.Error { Failure: Failure.InvalidSettings invalid }:
                return invalid.Problems;
            case Message.Error error:
                Trouble = new Trouble.Refused(error.Failure);
                return Items.Of<SettingsProblem>();
            case null:
                return Items.Of<SettingsProblem>();
            default:
                Trouble = new Trouble.Unexpected();
                return Items.Of<SettingsProblem>();
        }
    }

    /// <summary>Forgets the latest failed request.</summary>
    public void DismissTrouble() => Trouble = null;

    /// <summary>One connection, until it ends.</summary>
    private async Task FollowAsync(CancellationToken cancellation)
    {
        var loaded = false;
        try
        {
            await foreach (var message in daemon.WatchAsync(cancellation).ConfigureAwait(true))
            {
                switch (message)
                {
                    case Message.StatusReply status:
                        Connection = new Connection.Connected(status.Status);
                        if (!loaded)
                        {
                            loaded = true;
                            await LoadAsync().ConfigureAwait(true);
                        }

                        break;
                    case Message.Notice notice:
                        Notice = notice.Problem;
                        break;
                    default:
                        break;
                }
            }
        }
        catch (ClientException e)
        {
            Connection = new Connection.NoDaemon(e.Message);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            // The app is closing.
        }
    }

    /// <summary>The strategies and settings, once per connection.</summary>
    private async Task LoadAsync()
    {
        if (await AskAsync(new Request.GetStrategies()).ConfigureAwait(true) is Message.StrategiesReply reply)
        {
            Strategies = reply.Strategies;
        }

        if (await AskAsync(new Request.GetSettings()).ConfigureAwait(true) is Message.SettingsReply saved)
        {
            Settings = saved.Settings;
        }
    }

    /// <summary>Sends <paramref name="request"/>, which the daemon answers
    /// with done.</summary>
    private async Task ActAsync(Request request)
    {
        switch (await AskAsync(request).ConfigureAwait(true))
        {
            case Message.Done or null:
                break;
            default:
                Trouble = new Trouble.Unexpected();
                break;
        }
    }

    /// <summary>The daemon's answer, or <c>null</c> with
    /// <see cref="Trouble"/> set (an error answer included).</summary>
    private async Task<Message?> AskAsync(Request request)
    {
        var answer = await SendAsync(request).ConfigureAwait(true);
        if (answer is Message.Error error)
        {
            Trouble = new Trouble.Refused(error.Failure);
            return null;
        }

        return answer;
    }

    /// <summary>The daemon's answer, or <c>null</c> with
    /// <see cref="Trouble"/> set if it could not be asked.</summary>
    private async Task<Message?> SendAsync(Request request)
    {
        try
        {
            return await daemon.SendAsync(request, CancellationToken.None).ConfigureAwait(true);
        }
        catch (ClientException e)
        {
            Trouble = new Trouble.NotAsked(e.Failure);
            return null;
        }
    }

    /// <summary>Sets a property's field and announces the change, and of
    /// the properties computed from it.</summary>
    private void Set<T>(ref T field, T value, string[] computed, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        Changed(name);
        foreach (var other in computed)
        {
            Changed(other);
        }
    }

    private void Changed(string? name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
