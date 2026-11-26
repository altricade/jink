// The window the tray icon opens: the switch, what jink is doing, the
// strategy, finding one, and the way to the settings. It shows the model
// and calls it; nothing here decides anything.

using System.ComponentModel;
using Jink.Core;
using Jink.Protocol;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Jink.App;

internal sealed class MainWindow : Window
{
    private readonly AppModel model;
    private readonly App app;

    // Made by Build, filled by Refresh.
    private TextBlock connecting = new();
    private StackPanel noService = new();
    private TextBlock noServiceDetail = new();
    private StackPanel connected = new();
    private TextBlock status = new();
    private ToggleSwitch onOff = new();
    private InfoBar reinstall = new();
    private ComboBox strategy = new();
    private Button find = new();
    private StackPanel finding = new();
    private ProgressBar progress = new();
    private TextBlock found = new();
    private Expander details = new();
    private TextBlock notice = new();
    private InfoBar trouble = new();

    /// <summary>While the controls are set from the model, their own change
    /// events are not the person's.</summary>
    private bool refreshing;

    public MainWindow(AppModel model, App app)
    {
        this.model = model;
        this.app = app;
        Build();
        Ui.Frame(this, "jink", 380, 560);
        model.PropertyChanged += Changed;
    }

    /// <summary>Makes the controls (again, in the app's language).</summary>
    public void Build()
    {
        connecting = Ui.Text(Strings.Connecting, dim: true);
        noServiceDetail = Ui.Text(string.Empty, 12, dim: true);
        noServiceDetail.IsTextSelectionEnabled = true;
        noService = Ui.Column(
            8,
            Ui.Text(Strings.NoService, 16, bold: true),
            new Expander { Header = Strings.Details, Content = noServiceDetail, HorizontalAlignment = HorizontalAlignment.Stretch });

        status = Ui.Text(string.Empty, 13, dim: true);
        onOff = new ToggleSwitch { OnContent = string.Empty, OffContent = string.Empty, MinWidth = 0 };
        onOff.Toggled += (_, _) =>
        {
            if (!refreshing && onOff.IsOn != model.IsOn)
            {
                _ = model.SetOnAsync(onOff.IsOn);
            }
        };
        var header = new Grid { ColumnSpacing = 12 };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var title = Ui.Column(2, Ui.Text("jink", 20, bold: true), status);
        header.Children.Add(title);
        header.Children.Add(onOff);
        Grid.SetColumn(onOff, 1);

        reinstall = new InfoBar
        {
            Severity = InfoBarSeverity.Warning,
            Message = Strings.OtherVersion,
            IsClosable = false,
        };
        strategy = new ComboBox { Header = Strings.Strategy, HorizontalAlignment = HorizontalAlignment.Stretch };
        strategy.SelectionChanged += (_, _) =>
        {
            if (!refreshing && strategy.SelectedItem is ComboBoxItem { Tag: string id } && id != model.Status?.Strategy)
            {
                _ = model.ChooseAsync(id);
            }
        };
        find = Ui.Button(Strings.FindBest, () => _ = model.FindAsync());
        progress = new ProgressBar { Minimum = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        finding = Ui.Column(
            6,
            progress,
            Ui.Text(Strings.FindTakesTime, 12, dim: true),
            Ui.Button(Strings.Cancel, () => _ = model.CancelFindAsync()));
        found = Ui.Text(string.Empty, 13);
        details = new Expander { Header = Strings.Details, HorizontalAlignment = HorizontalAlignment.Stretch };
        notice = Ui.Text(string.Empty, 12, dim: true);
        connected = Ui.Column(14, header, reinstall, strategy, find, finding, found, details, notice);

        trouble = new InfoBar { Severity = InfoBarSeverity.Error, IsClosable = true };
        trouble.CloseButtonClick += (_, _) => model.DismissTrouble();

        var footer = new Grid();
        var settings = Ui.Button(Strings.Settings, app.ShowSettings);
        var quit = Ui.Button(Strings.Quit, app.Quit);
        quit.HorizontalAlignment = HorizontalAlignment.Right;
        footer.Children.Add(settings);
        footer.Children.Add(quit);

        var body = Ui.Column(14, connecting, noService, connected, trouble);
        var root = new Grid { Padding = new Thickness(20), RowSpacing = 14 };
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.Children.Add(new ScrollViewer { Content = body });
        root.Children.Add(footer);
        Grid.SetRow(footer, 1);
        Ui.Background(root);
        Content = root;
        Refresh();
    }

    private void Changed(object? sender, PropertyChangedEventArgs e) => Refresh();

    /// <summary>Shows the model's state.</summary>
    private void Refresh()
    {
        refreshing = true;
        try
        {
            connecting.Visibility = Shown(model.Connection is Connection.Connecting);
            noService.Visibility = Shown(model.Connection is Connection.NoDaemon);
            if (model.Connection is Connection.NoDaemon none)
            {
                noServiceDetail.Text = none.Detail;
            }

            connected.Visibility = Shown(model.Status is not null);
            if (model.Status is { } now)
            {
                RefreshStatus(now);
            }

            trouble.IsOpen = model.Trouble is not null;
            trouble.Message = model.Trouble is { } failed ? Explain.Trouble(failed) : string.Empty;
        }
        finally
        {
            refreshing = false;
        }
    }

    private void RefreshStatus(Status now)
    {
        status.Text = Describe.Engine(now.Engine, model.NameOf);
        if (model.Indicator == Indicator.Trouble && Ui.Critical() is { } red)
        {
            status.Foreground = red;
        }
        else
        {
            status.ClearValue(TextBlock.ForegroundProperty);
        }

        onOff.IsOn = model.IsOn;
        onOff.IsEnabled = !model.IsFinding;
        reinstall.IsOpen = model.NeedsReinstall;
        reinstall.Visibility = Shown(model.NeedsReinstall);

        RefreshStrategies(now.Strategy);
        strategy.IsEnabled = !model.IsFinding;

        find.Visibility = Shown(!model.IsFinding);
        finding.Visibility = Shown(model.IsFinding);
        if (now.Engine is Engine.Finding step)
        {
            progress.Maximum = Math.Max(step.Of, 1);
            progress.Value = step.Step;
        }

        found.Visibility = Shown(now.Found is not null);
        details.Visibility = Shown(now.Found is not null);
        if (now.Found is { } result)
        {
            found.Text = Describe.Found(result, model.NameOf);
            details.Content = Details(result);
        }

        notice.Visibility = Shown(model.Notice is not null);
        notice.Text = model.Notice is { } problem ? Explain.Problem(problem) : string.Empty;
    }

    /// <summary>The picker's items: each main strategy, its variants under
    /// it (indented), the current one chosen.</summary>
    private void RefreshStrategies(string current)
    {
        var wanted = model.Groups
            .SelectMany(g => g.Variants.Select(v => (Strategy: v, Variant: true)).Prepend((Strategy: g.Main, Variant: false)))
            .ToList();
        var same = strategy.Items.Count == wanted.Count
            && strategy.Items.Zip(wanted).All(p => p.First is ComboBoxItem { Tag: string id } && id == p.Second.Strategy.Id);
        if (!same)
        {
            strategy.Items.Clear();
            foreach (var (info, variant) in wanted)
            {
                strategy.Items.Add(new ComboBoxItem
                {
                    Content = Describe.Strategy(info),
                    Tag = info.Id,
                    Padding = new Thickness(variant ? 28 : 12, 6, 12, 6),
                });
            }
        }

        strategy.SelectedItem = strategy.Items.FirstOrDefault(i => i is ComboBoxItem { Tag: string id } && id == current);
    }

    /// <summary>How the sites answered without jink and with each strategy
    /// tried; the failed checks show on hover.</summary>
    private Grid Details(Found result)
    {
        var grid = new Grid { ColumnSpacing = 16, RowSpacing = 4 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var rows = result.Tried
            .Select(t => (Name: model.NameOf(t.Strategy), t.Checks, t.Problem))
            .Prepend((Name: Strings.WithoutJink, Checks: result.Without, Problem: (Problem?)null))
            .ToList();
        foreach (var (row, index) in rows.Select((r, i) => (r, i)))
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var (outcome, failures) = Describe.Round(row.Checks, result.Checks, row.Problem);
            var name = Ui.Text(row.Name, 12);
            var value = Ui.Text(outcome, 12, dim: true);
            if (failures.Length > 0)
            {
                ToolTipService.SetToolTip(value, failures);
            }

            grid.Children.Add(name);
            grid.Children.Add(value);
            Grid.SetRow(name, index);
            Grid.SetRow(value, index);
            Grid.SetColumn(value, 1);
        }

        return grid;
    }

    private static Visibility Shown(bool shown) => shown ? Visibility.Visible : Visibility.Collapsed;
}
