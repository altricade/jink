// The settings window: General (start with Windows, open at sign-in,
// language), Sites, IPs and Gaming. The lists are a draft until saved; the
// service checks them and says which entries are not valid.

using System.ComponentModel;
using Jink.Core;
using Jink.Protocol;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Jink.App;

internal sealed class SettingsWindow : Window
{
    private readonly AppModel model;
    private readonly App app;

    /// <summary>The settings as saved, and as edited.</summary>
    private Settings? saved;
    private Draft? draft;

    /// <summary>The invalid entries the service named at the last
    /// save.</summary>
    private Items<SettingsProblem> problems = Items.Of<SettingsProblem>();

    private TextBlock later = new();
    private Grid form = new();
    private ToggleSwitch startWithWindows = new();
    private TextBox mySites = new();
    private TextBox excludedSites = new();
    private TextBox myIps = new();
    private TextBox excludedIps = new();
    private ComboBox ipList = new();
    private ToggleSwitch gaming = new();
    private ComboBox protocols = new();
    private TextBox tcpPorts = new();
    private TextBox udpPorts = new();
    private TextBlock notSaved = new();
    private Button revert = new();
    private Button save = new();
    private readonly Dictionary<string, TextBlock> fieldProblems = [];

    /// <summary>While the controls are set from the draft, their own change
    /// events are not the person's.</summary>
    private bool refreshing;

    public SettingsWindow(AppModel model, App app)
    {
        this.model = model;
        this.app = app;
        Build();
        Ui.Frame(this, "jink", 560, 640);
        AppWindow.Hide();
        model.PropertyChanged += Changed;
    }

    /// <summary>Makes the controls (again, in the app's language).</summary>
    public void Build()
    {
        fieldProblems.Clear();
        later = Ui.Text(Strings.SettingsLater, dim: true);

        var pages = new Dictionary<string, UIElement>
        {
            ["general"] = General(),
            ["sites"] = Ui.Column(
                18,
                List(Strings.MySites, Strings.MySitesHint, "my_sites", out mySites, (d, t) => d with { MySites = t }),
                List(Strings.ExcludedSites, Strings.ExcludedSitesHint, "excluded_sites", out excludedSites, (d, t) => d with { ExcludedSites = t })),
            ["ips"] = Ips(),
            ["gaming"] = Gaming(),
        };
        var page = new ScrollViewer { Padding = new Thickness(0, 12, 12, 0) };
        var bar = new SelectorBar();
        foreach (var (tag, text, symbol) in new[]
        {
            ("general", Strings.General, Symbol.Setting),
            ("sites", Strings.Sites, Symbol.World),
            ("ips", Strings.Ips, Symbol.Globe),
            ("gaming", Strings.Gaming, Symbol.Play),
        })
        {
            bar.Items.Add(new SelectorBarItem { Text = text, Tag = tag, Icon = new SymbolIcon(symbol) });
        }

        bar.SelectionChanged += (_, _) =>
        {
            if (bar.SelectedItem is SelectorBarItem { Tag: string tag })
            {
                page.Content = pages[tag];
            }
        };
        bar.SelectedItem = bar.Items[0];

        notSaved = Ui.Text(Strings.NotSaved, 13);
        notSaved.Foreground = Ui.Critical();
        notSaved.VerticalAlignment = VerticalAlignment.Center;
        revert = Ui.Button(Strings.Revert, Revert);
        save = Ui.Button(Strings.Save, () => _ = SaveAsync(), accent: true);
        var footer = new Grid { ColumnSpacing = 8 };
        footer.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        footer.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        footer.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        footer.Children.Add(notSaved);
        footer.Children.Add(revert);
        footer.Children.Add(save);
        Grid.SetColumn(revert, 1);
        Grid.SetColumn(save, 2);

        form = new Grid { RowSpacing = 12 };
        form.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        form.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        form.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        form.Children.Add(bar);
        form.Children.Add(page);
        form.Children.Add(footer);
        Grid.SetRow(page, 1);
        Grid.SetRow(footer, 2);

        var root = new Grid { Padding = new Thickness(20) };
        root.Children.Add(later);
        root.Children.Add(form);
        Ui.Background(root);
        Content = root;
        Refresh();
    }

    private StackPanel General()
    {
        startWithWindows = new ToggleSwitch { Header = Strings.StartWithWindows };
        startWithWindows.Toggled += (_, _) =>
        {
            if (!refreshing && startWithWindows.IsOn != model.Status?.StartAtBoot)
            {
                _ = model.SetStartAtBootAsync(startWithWindows.IsOn);
            }
        };
        var signIn = new ToggleSwitch { Header = Strings.OpenAtSignIn, IsOn = Preferences.OpenAtSignIn };
        signIn.Toggled += (_, _) => Preferences.OpenAtSignIn = signIn.IsOn;
        var language = new ComboBox { Header = Strings.Language, MinWidth = 220 };
        foreach (var (choice, text) in new[]
        {
            (Language.System, Strings.LanguageSystem),
            (Language.English, "English"),
            (Language.Russian, "Русский"),
        })
        {
            language.Items.Add(new ComboBoxItem { Content = text, Tag = choice });
        }

        var chosen = Preferences.Language;
        language.SelectedItem = language.Items.FirstOrDefault(i => i is ComboBoxItem { Tag: Language l } && l == chosen);
        language.SelectionChanged += (_, _) =>
        {
            if (language.SelectedItem is ComboBoxItem { Tag: Language picked } && picked != Preferences.Language)
            {
                app.ChangeLanguage(picked);
            }
        };
        return Ui.Column(18, startWithWindows, signIn, language);
    }

    private StackPanel Ips()
    {
        ipList = new ComboBox { Header = Strings.IpList, MinWidth = 220 };
        foreach (var (choice, text) in new[]
        {
            (IpList.Off, Strings.IpListOff),
            (IpList.BuiltIn, Strings.IpListBuiltIn),
            (IpList.All, Strings.IpListAll),
        })
        {
            ipList.Items.Add(new ComboBoxItem { Content = text, Tag = choice });
        }

        ipList.SelectionChanged += (_, _) =>
        {
            if (ipList.SelectedItem is ComboBoxItem { Tag: IpList picked })
            {
                Edit(d => d with { IpList = picked });
            }
        };
        return Ui.Column(
            18,
            List(Strings.MyIps, Strings.MyIpsHint, "my_ips", out myIps, (d, t) => d with { MyIps = t }),
            List(Strings.ExcludedIps, Strings.ExcludedIpsHint, "excluded_ips", out excludedIps, (d, t) => d with { ExcludedIps = t }),
            Ui.Column(4, ipList, Ui.Text(Strings.IpListHint, 12, dim: true)));
    }

    private StackPanel Gaming()
    {
        gaming = new ToggleSwitch { Header = Strings.GamingMode };
        gaming.Toggled += (_, _) => Edit(d => d.GamingOn == gaming.IsOn ? d : d.WithGaming(gaming.IsOn));
        protocols = new ComboBox { Header = Strings.Protocols, MinWidth = 220 };
        foreach (var (choice, text) in new[]
        {
            (GamingMode.Off, Strings.Off),
            (GamingMode.Tcp, "TCP"),
            (GamingMode.Udp, "UDP"),
            (GamingMode.Both, Strings.TcpAndUdp),
        })
        {
            protocols.Items.Add(new ComboBoxItem { Content = text, Tag = choice });
        }

        protocols.SelectionChanged += (_, _) =>
        {
            if (protocols.SelectedItem is ComboBoxItem { Tag: GamingMode picked })
            {
                Edit(d => d with { Gaming = d.Gaming with { Mode = picked } });
            }
        };
        tcpPorts = Ports(Strings.TcpPorts, (d, t) => d with { Gaming = d.Gaming with { TcpPorts = t } });
        udpPorts = Ports(Strings.UdpPorts, (d, t) => d with { Gaming = d.Gaming with { UdpPorts = t } });
        var advanced = new Expander
        {
            Header = Strings.Advanced,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Content = Ui.Column(
                12,
                protocols,
                tcpPorts,
                Problems("gaming.tcp_ports"),
                udpPorts,
                Problems("gaming.udp_ports")),
        };
        return Ui.Column(18, Ui.Column(4, gaming, Ui.Text(Strings.GamingHint, 12, dim: true)), advanced);
    }

    /// <summary>A list edited as text, one entry per line, with its hint and
    /// its invalid entries.</summary>
    private StackPanel List(
        string header,
        string hint,
        string field,
        out TextBox box,
        Func<Draft, string, Draft> write)
    {
        var edit = new TextBox
        {
            Header = header,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.NoWrap,
            Height = 130,
        };
        ScrollViewer.SetVerticalScrollBarVisibility(edit, ScrollBarVisibility.Auto);
        edit.TextChanged += (_, _) => Edit(d => write(d, edit.Text));
        box = edit;
        return Ui.Column(4, edit, Ui.Text(hint, 12, dim: true), Problems(field));
    }

    private TextBox Ports(string header, Func<Draft, string, Draft> write)
    {
        var edit = new TextBox { Header = header, MaxWidth = 220, HorizontalAlignment = HorizontalAlignment.Left };
        edit.TextChanged += (_, _) => Edit(d => write(d, edit.Text));
        return edit;
    }

    /// <summary>Where the invalid entries of <paramref name="field"/>
    /// show.</summary>
    private TextBlock Problems(string field)
    {
        var text = Ui.Text(string.Empty, 12);
        text.Foreground = Ui.Critical();
        fieldProblems[field] = text;
        return text;
    }

    private void Changed(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(AppModel.Settings) or nameof(AppModel.Connection))
        {
            Refresh();
        }
    }

    /// <summary>Takes the saved settings when they change (an unchanged draft
    /// follows them; an edited one stays), and shows the draft.</summary>
    private void Refresh()
    {
        var latest = model.Settings;
        if (latest != saved)
        {
            var untouched = draft is null || saved is null || draft == Draft.Of(saved);
            saved = latest;
            if (untouched && latest is not null)
            {
                draft = Draft.Of(latest);
            }
        }

        later.Visibility = latest is null ? Visibility.Visible : Visibility.Collapsed;
        form.Visibility = latest is null ? Visibility.Collapsed : Visibility.Visible;
        refreshing = true;
        try
        {
            startWithWindows.IsOn = model.Status?.StartAtBoot ?? false;
            startWithWindows.IsEnabled = model.Status is not null;
            if (draft is { } shown)
            {
                Show(shown);
            }
        }
        finally
        {
            refreshing = false;
        }
    }

    private void Show(Draft shown)
    {
        SetText(mySites, shown.MySites);
        SetText(excludedSites, shown.ExcludedSites);
        SetText(myIps, shown.MyIps);
        SetText(excludedIps, shown.ExcludedIps);
        SetText(tcpPorts, shown.Gaming.TcpPorts);
        SetText(udpPorts, shown.Gaming.UdpPorts);
        gaming.IsOn = shown.GamingOn;
        Select(ipList, shown.IpList);
        Select(protocols, shown.Gaming.Mode);

        var sent = shown.ToSettings();
        foreach (var (field, text) in fieldProblems)
        {
            text.Text = string.Join('\n', problems
                .Where(p => p.Field == field)
                .Select(p => Entry(sent, p) is { } entry ? $"{entry}: {Explain.Entry(p)}" : Explain.Entry(p)));
            text.Visibility = text.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        notSaved.Visibility = problems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        var edited = saved is not null && shown != Draft.Of(saved);
        revert.IsEnabled = edited;
        save.IsEnabled = edited;
    }

    /// <summary>The entry a problem is about (problems name entries by their
    /// place in the list sent).</summary>
    private static string? Entry(Settings sent, SettingsProblem problem)
    {
        var list = problem.Field switch
        {
            "my_sites" => sent.MySites,
            "excluded_sites" => sent.ExcludedSites,
            "my_ips" => sent.MyIps,
            "excluded_ips" => sent.ExcludedIps,
            _ => null,
        };
        return list is not null && problem.Index is { } index && index >= 0 && index < list.Count ? list[index] : null;
    }

    private void Edit(Func<Draft, Draft> change)
    {
        if (refreshing || draft is null)
        {
            return;
        }

        draft = change(draft);
        refreshing = true;
        try
        {
            Show(draft);
        }
        finally
        {
            refreshing = false;
        }
    }

    private void Revert()
    {
        problems = Items.Of<SettingsProblem>();
        draft = saved is null ? null : Draft.Of(saved);
        Refresh();
    }

    private async Task SaveAsync()
    {
        if (draft is null)
        {
            return;
        }

        save.IsEnabled = false;
        problems = await model.SaveAsync(draft.ToSettings()).ConfigureAwait(true);
        if (problems.Count == 0 && model.Settings is { } normalized)
        {
            // The service's own form of the entries (links become domains).
            saved = normalized;
            draft = Draft.Of(normalized);
        }

        Refresh();
    }

    private static void SetText(TextBox box, string text)
    {
        if (box.Text != text)
        {
            box.Text = text;
        }
    }

    private static void Select<T>(ComboBox box, T value)
        where T : struct, Enum =>
        box.SelectedItem = box.Items.FirstOrDefault(i => i is ComboBoxItem { Tag: T tag } && tag.Equals(value));
}
