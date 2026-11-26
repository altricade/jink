// The app's start: one copy per person (a second start shows the first
// one's window), then WinUI on this thread.

using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace Jink.App;

internal static class Program
{
    /// <summary>Starts in the tray only, without showing the window (as at
    /// sign-in).</summary>
    public const string Hidden = "--hidden";

    private const string OneCopy = @"Local\jink-app";
    private const string ShowCall = @"Local\jink-app-show";

    /// <summary>The app, held for as long as it runs.</summary>
    private static App? app;

    [STAThread]
    private static int Main(string[] args)
    {
        using var copy = new Mutex(initiallyOwned: true, OneCopy, out var first);
        using var show = new EventWaitHandle(initialState: false, EventResetMode.AutoReset, ShowCall);
        if (!first)
        {
            // jink already runs: show its window instead.
            show.Set();
            return 0;
        }

        WinRT.ComWrappersSupport.InitializeComWrappers();
        Application.Start(_ =>
        {
            SynchronizationContext.SetSynchronizationContext(
                new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
            app = new App(show, hidden: args.Contains(Hidden, StringComparer.OrdinalIgnoreCase));
        });
        app?.Dispose();
        return 0;
    }
}
