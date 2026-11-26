// Small pieces the windows are made of.

using System.Windows.Input;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;

namespace Jink.App;

/// <summary>A command that runs an action.</summary>
internal sealed class Command(Action run) : ICommand
{
    public event EventHandler? CanExecuteChanged
    {
        add { }
        remove { }
    }

    public bool CanExecute(object? parameter) => true;

    public void Execute(object? parameter) => run();
}

/// <summary>Builders for the controls the windows use.</summary>
internal static class Ui
{
    /// <summary>The folder the app runs from (its icons are there).</summary>
    public static string Assets => Path.Combine(AppContext.BaseDirectory, "Assets");

    public static TextBlock Text(string text, double size = 14, bool bold = false, bool dim = false) => new()
    {
        Text = text,
        FontSize = size,
        FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
        TextWrapping = TextWrapping.Wrap,
        Opacity = dim ? 0.7 : 1,
    };

    public static Button Button(string text, Action click, bool accent = false)
    {
        var button = new Button { Content = text };
        if (accent && Application.Current.Resources.TryGetValue("AccentButtonStyle", out var style))
        {
            button.Style = (Style)style;
        }

        button.Click += (_, _) => click();
        return button;
    }

    public static StackPanel Column(double spacing, params UIElement[] children)
    {
        var column = new StackPanel { Spacing = spacing };
        foreach (var child in children)
        {
            column.Children.Add(child);
        }

        return column;
    }

    public static StackPanel Row(double spacing, params UIElement[] children)
    {
        var row = Column(spacing, children);
        row.Orientation = Orientation.Horizontal;
        return row;
    }

    /// <summary>Sets up <paramref name="window"/> as one of jink's: title,
    /// icon, fixed size in view pixels (scaled to the display), the Mica
    /// backdrop where Windows has it, and hidden (not closed) by its close
    /// button.</summary>
    public static void Frame(Window window, string title, int width, int height)
    {
        window.Title = title;
        var app = window.AppWindow;
        app.SetIcon(Path.Combine(Assets, "jink.ico"));
        if (app.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsResizable = false;
            presenter.IsMaximizable = false;
        }

        if (MicaController.IsSupported())
        {
            window.SystemBackdrop = new MicaBackdrop();
        }

        app.Closing += (_, e) =>
        {
            e.Cancel = true;
            app.Hide();
        };
        Size(window, width, height);
    }

    /// <summary>Gives <paramref name="window"/>'s content the page
    /// background unless Mica shows behind it.</summary>
    public static void Background(Panel content)
    {
        if (!MicaController.IsSupported()
            && Application.Current.Resources.TryGetValue("ApplicationPageBackgroundThemeBrush", out var brush))
        {
            content.Background = (Brush)brush;
        }
    }

    /// <summary>The theme's colour for problems.</summary>
    public static Brush? Critical() =>
        Application.Current.Resources.TryGetValue("SystemFillColorCriticalBrush", out var brush) ? (Brush)brush : null;

    /// <summary>Shows <paramref name="window"/> in front.</summary>
    public static void Show(Window window)
    {
        window.AppWindow.Show();
        window.Activate();
    }

    private static void Size(Window window, int width, int height)
    {
        void Resize()
        {
            var scale = window.Content?.XamlRoot?.RasterizationScale ?? 1.0;
            window.AppWindow.Resize(new SizeInt32((int)(width * scale), (int)(height * scale)));
        }

        Resize();
        window.Activated += (_, _) => Resize();
    }
}
