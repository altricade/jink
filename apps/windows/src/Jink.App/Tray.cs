// The tray icon: what jink does at a glance (off, busy, on, trouble), the
// window on a click, and a menu on a right-click.

using System.ComponentModel;
using System.Drawing;
using H.NotifyIcon;
using Jink.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Controls;
using Windows.UI.ViewManagement;

namespace Jink.App;

internal sealed class Tray : IDisposable
{
    private readonly AppModel model;
    private readonly App app;
    private readonly TaskbarIcon icon;
    private readonly Dictionary<string, Icon> icons = [];
    private readonly UISettings theme = new();
    private readonly MenuFlyoutItem toggle = new();

    public Tray(AppModel model, App app)
    {
        this.model = model;
        this.app = app;
        icon = new TaskbarIcon
        {
            ContextMenuMode = ContextMenuMode.PopupMenu,
            NoLeftClickDelay = true,
            LeftClickCommand = new Command(app.ToggleMain),
        };
        Build();
        model.PropertyChanged += Changed;
        // Windows tells of a theme change off the UI thread.
        var queue = DispatcherQueue.GetForCurrentThread();
        theme.ColorValuesChanged += (_, _) => queue.TryEnqueue(Refresh);
        icon.ForceCreate();
    }

    /// <summary>Makes the menu (again, in the app's language).</summary>
    public void Build()
    {
        var menu = new MenuFlyout();
        menu.Items.Add(new MenuFlyoutItem { Text = "jink", Command = new Command(app.ShowMain) });
        toggle.Command = new Command(() => _ = model.SetOnAsync(!model.IsOn));
        menu.Items.Add(toggle);
        menu.Items.Add(new MenuFlyoutItem { Text = Strings.Settings, Command = new Command(app.ShowSettings) });
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(new MenuFlyoutItem { Text = Strings.Quit, Command = new Command(app.Quit) });
        icon.ContextFlyout = menu;
        Refresh();
    }

    public void Dispose()
    {
        model.PropertyChanged -= Changed;
        icon.Dispose();
        foreach (var loaded in icons.Values)
        {
            loaded.Dispose();
        }
    }

    private void Changed(object? sender, PropertyChangedEventArgs e) => Refresh();

    private void Refresh()
    {
        var state = model.Indicator switch
        {
            Indicator.Busy => "busy",
            Indicator.On => "on",
            Indicator.Trouble => "trouble",
            _ => "off",
        };
        var name = $"tray-{state}-{(Preferences.LightTaskbar ? "light" : "dark")}.ico";
        if (!icons.TryGetValue(name, out var shown))
        {
            shown = new Icon(Path.Combine(Ui.Assets, name));
            icons[name] = shown;
        }

        icon.UpdateIcon(shown);
        icon.ToolTipText = "jink: " + (model.Status is { } status
            ? Describe.Engine(status.Engine, model.NameOf)
            : model.Connection is Connection.NoDaemon ? Strings.NoService : Strings.Connecting);
        toggle.Text = model.IsOn ? Strings.TurnOff : Strings.TurnOn;
        toggle.IsEnabled = model.Status is not null && !model.IsFinding;
    }
}
