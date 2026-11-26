// The app's own choices, apart from the service's settings: its language
// (in %LocalAppData%\jink\app.json) and whether it opens at sign-in (the
// per-person Run key, which the installer also sets).

using System.Globalization;
using System.Text.Json;
using Microsoft.Win32;

namespace Jink.App;

/// <summary>Which language the app shows.</summary>
internal enum Language
{
    /// <summary>Windows' display language.</summary>
    System,

    /// <summary>English.</summary>
    English,

    /// <summary>Russian.</summary>
    Russian,
}

/// <summary>Reads and keeps the app's choices.</summary>
internal static class Preferences
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunName = "jink";

    private static string File =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "jink", "app.json");

    /// <summary>The chosen language (Windows' if none, or if the file is
    /// unreadable).</summary>
    public static Language Language
    {
        get
        {
            try
            {
                using var json = JsonDocument.Parse(System.IO.File.ReadAllText(File));
                return json.RootElement.TryGetProperty("language", out var value) ? value.GetString() switch
                {
                    "en" => Language.English,
                    "ru" => Language.Russian,
                    _ => Language.System,
                } : Language.System;
            }
            catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException or InvalidOperationException)
            {
                return Language.System;
            }
        }

        set
        {
            Directory.CreateDirectory(Path.GetDirectoryName(File) ?? ".");
            var code = value switch
            {
                Language.English => "en",
                Language.Russian => "ru",
                _ => "system",
            };
            System.IO.File.WriteAllText(File, JsonSerializer.Serialize(new Dictionary<string, string> { ["language"] = code }));
        }
    }

    /// <summary>The culture for <paramref name="language"/>; <c>null</c>
    /// follows Windows.</summary>
    public static CultureInfo? Culture(Language language) => language switch
    {
        Language.English => CultureInfo.GetCultureInfo("en"),
        Language.Russian => CultureInfo.GetCultureInfo("ru"),
        _ => null,
    };

    /// <summary>Whether the app opens (in the tray) when the person signs
    /// in.</summary>
    public static bool OpenAtSignIn
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(RunName) is string;
        }

        set
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (value)
            {
                key.SetValue(RunName, $"\"{Environment.ProcessPath}\" {Program.Hidden}");
            }
            else
            {
                key.DeleteValue(RunName, throwOnMissingValue: false);
            }
        }
    }

    /// <summary>Whether the taskbar is light (then the tray icons are
    /// black; on a dark one, white).</summary>
    public static bool LightTaskbar
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("SystemUsesLightTheme") is int light && light != 0;
        }
    }
}
