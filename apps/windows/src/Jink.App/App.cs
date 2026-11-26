// The app: the model following the service, the tray icon, and the two
// windows. It lives in the tray; closing a window only hides it, and Quit
// in the tray ends it (desync goes on in the service).

using System.Reflection;
using Jink.Client;
using Jink.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Jink.App;

internal sealed class App : Application, IDisposable
{
    /// <summary>How long to wait before trying the service again.</summary>
    private static readonly TimeSpan Retry = TimeSpan.FromSeconds(2);

    private readonly EventWaitHandle showCall;
    private readonly bool hidden;
    private readonly CancellationTokenSource running = new();
    private AppModel? model;
    private Tray? tray;
    private MainWindow? main;
    private SettingsWindow? settings;

    public App(EventWaitHandle showCall, bool hidden)
    {
        this.showCall = showCall;
        this.hidden = hidden;
    }

    /// <summary>This app's version (the service's should be the
    /// same).</summary>
    private static string Version
    {
        get
        {
            var version = typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
            var build = version.IndexOf('+', StringComparison.Ordinal);
            return build < 0 ? version : version[..build];
        }
    }

    /// <summary>Shows the main window (from the tray, or a second
    /// start).</summary>
    public void ShowMain()
    {
        if (main is not null)
        {
            Ui.Show(main);
        }
    }

    /// <summary>Shows the main window, or hides it if it is in
    /// front.</summary>
    public void ToggleMain()
    {
        if (main is null)
        {
            return;
        }

        if (main.AppWindow.IsVisible)
        {
            main.AppWindow.Hide();
        }
        else
        {
            Ui.Show(main);
        }
    }

    public void ShowSettings()
    {
        if (settings is not null)
        {
            Ui.Show(settings);
        }
    }

    /// <summary>Shows everything in the chosen language.</summary>
    public void ChangeLanguage(Language language)
    {
        Preferences.Language = language;
        Strings.Culture = Preferences.Culture(language);
        main?.Build();
        settings?.Build();
        tray?.Build();
    }

    /// <summary>Ends the app (desync goes on in the service).</summary>
    public void Quit()
    {
        running.Cancel();
        tray?.Dispose();
        tray = null;
        Exit();
    }

    public void Dispose()
    {
        running.Cancel();
        running.Dispose();
        tray?.Dispose();
        tray = null;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        Resources.MergedDictionaries.Add(new XamlControlsResources());
        Strings.Culture = Preferences.Culture(Preferences.Language);
        model = new AppModel(new DaemonClient(), Version, Retry);
        main = new MainWindow(model, this);
        settings = new SettingsWindow(model, this);
        tray = new Tray(model, this);
        _ = model.RunAsync(running.Token);
        if (!hidden)
        {
            Ui.Show(main);
        }

        AnswerShowCalls();
    }

    /// <summary>A second start of the app asks this one to show its window.</summary>
    private void AnswerShowCalls()
    {
        var queue = DispatcherQueue.GetForCurrentThread();
        var waiter = new Thread(() =>
        {
            while (WaitHandle.WaitAny([showCall, running.Token.WaitHandle]) == 0)
            {
                queue.TryEnqueue(ShowMain);
            }
        })
        {
            IsBackground = true,
            Name = "show calls",
        };
        waiter.Start();
    }
}
