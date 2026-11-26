// The app's text in its language: Resources/Strings.resx (English) and
// Strings.ru.resx (Russian). The tests check that every text here has both.

using System.Globalization;
using System.Resources;

namespace Jink.Core;

/// <summary>The app's text, in <see cref="Culture"/> (the system's language
/// unless the person chose one).</summary>
public static class Strings
{
    private static readonly ResourceManager Resources =
        new("Jink.Core.Resources.Strings", typeof(Strings).Assembly);

    /// <summary>The language to show; <c>null</c> follows Windows.</summary>
    public static CultureInfo? Culture { get; set; }

    /// <summary>The text named <paramref name="key"/> in
    /// <paramref name="culture"/>, if there is one (for the tests).</summary>
    public static string? Find(string key, CultureInfo culture) => Resources.GetString(key, culture);

    private static string Get(string key) =>
        Resources.GetString(key, Culture ?? CultureInfo.CurrentUICulture) ?? key;

    private static string Format(string key, params object[] args) =>
        string.Format(Culture ?? CultureInfo.CurrentUICulture, Get(key), args);

    /// <summary>"Off"</summary>
    public static string Off => Get(nameof(Off));

    /// <summary>"Starting…"</summary>
    public static string Starting => Get(nameof(Starting));

    /// <summary>"On, checking the network…"</summary>
    public static string OnChecking => Get(nameof(OnChecking));

    /// <summary>"On"</summary>
    public static string On => Get(nameof(On));

    /// <summary>"On, via {0}"</summary>
    public static string OnVia(object arg0) => Format(nameof(OnVia), arg0);

    /// <summary>"On, waiting for a network"</summary>
    public static string OnWaiting => Get(nameof(OnWaiting));

    /// <summary>"On, but not working: {0}"</summary>
    public static string OnNotWorking(object arg0) => Format(nameof(OnNotWorking), arg0);

    /// <summary>"Stopped: {0}"</summary>
    public static string Stopped(object arg0) => Format(nameof(Stopped), arg0);

    /// <summary>"Finding a strategy…"</summary>
    public static string Finding => Get(nameof(Finding));

    /// <summary>"Finding a strategy: trying {0}"</summary>
    public static string FindingTrying(object arg0) => Format(nameof(FindingTrying), arg0);

    /// <summary>"Connecting to the background service…"</summary>
    public static string Connecting => Get(nameof(Connecting));

    /// <summary>"jink's background service is not running. Reinstall jink to fix it."</summary>
    public static string NoService => Get(nameof(NoService));

    /// <summary>"The background service is from another version of jink. Reinstall jink to fix it."</summary>
    public static string OtherVersion => Get(nameof(OtherVersion));

    /// <summary>"Strategy"</summary>
    public static string Strategy => Get(nameof(Strategy));

    /// <summary>"{0} (partly)"</summary>
    public static string Partly(object arg0) => Format(nameof(Partly), arg0);

    /// <summary>"Find the best strategy"</summary>
    public static string FindBest => Get(nameof(FindBest));

    /// <summary>"Takes a minute or two. Sites may not open meanwhile."</summary>
    public static string FindTakesTime => Get(nameof(FindTakesTime));

    /// <summary>"Cancel"</summary>
    public static string Cancel => Get(nameof(Cancel));

    /// <summary>"Kept {0}: {1} of {2} checks passed ({3} without jink)."</summary>
    public static string Kept(object arg0, object arg1, object arg2, object arg3) => Format(nameof(Kept), arg0, arg1, arg2, arg3);

    /// <summary>"Nothing is blocked here: every site works without jink."</summary>
    public static string NothingBlocked => Get(nameof(NothingBlocked));

    /// <summary>"No strategy did better than without jink."</summary>
    public static string NoneHelped => Get(nameof(NoneHelped));

    /// <summary>"No network: the sites could not be reached at all."</summary>
    public static string NoNetwork => Get(nameof(NoNetwork));

    /// <summary>"Details"</summary>
    public static string Details => Get(nameof(Details));

    /// <summary>"Without jink"</summary>
    public static string WithoutJink => Get(nameof(WithoutJink));

    /// <summary>"Settings…"</summary>
    public static string Settings => Get(nameof(Settings));

    /// <summary>"Quit"</summary>
    public static string Quit => Get(nameof(Quit));

    /// <summary>"General"</summary>
    public static string General => Get(nameof(General));

    /// <summary>"Sites"</summary>
    public static string Sites => Get(nameof(Sites));

    /// <summary>"IPs"</summary>
    public static string Ips => Get(nameof(Ips));

    /// <summary>"Gaming"</summary>
    public static string Gaming => Get(nameof(Gaming));

    /// <summary>"Turn on when Windows starts"</summary>
    public static string StartWithWindows => Get(nameof(StartWithWindows));

    /// <summary>"Open jink when I sign in"</summary>
    public static string OpenAtSignIn => Get(nameof(OpenAtSignIn));

    /// <summary>"Language"</summary>
    public static string Language => Get(nameof(Language));

    /// <summary>"As Windows"</summary>
    public static string LanguageSystem => Get(nameof(LanguageSystem));

    /// <summary>"My sites"</summary>
    public static string MySites => Get(nameof(MySites));

    /// <summary>"Sites jink should also unblock: one per line; links are fine."</summary>
    public static string MySitesHint => Get(nameof(MySitesHint));

    /// <summary>"Excluded sites"</summary>
    public static string ExcludedSites => Get(nameof(ExcludedSites));

    /// <summary>"Sites jink should leave alone."</summary>
    public static string ExcludedSitesHint => Get(nameof(ExcludedSitesHint));

    /// <summary>"My IPs"</summary>
    public static string MyIps => Get(nameof(MyIps));

    /// <summary>"Addresses or networks (1.2.3.0/24) jink should also unblock."</summary>
    public static string MyIpsHint => Get(nameof(MyIpsHint));

    /// <summary>"Excluded IPs"</summary>
    public static string ExcludedIps => Get(nameof(ExcludedIps));

    /// <summary>"Addresses or networks jink should leave alone."</summary>
    public static string ExcludedIpsHint => Get(nameof(ExcludedIpsHint));

    /// <summary>"IP list"</summary>
    public static string IpList => Get(nameof(IpList));

    /// <summary>"Also treat traffic to these addresses, whatever the site name."</summary>
    public static string IpListHint => Get(nameof(IpListHint));

    /// <summary>"Off"</summary>
    public static string IpListOff => Get(nameof(IpListOff));

    /// <summary>"Built-in list"</summary>
    public static string IpListBuiltIn => Get(nameof(IpListBuiltIn));

    /// <summary>"All addresses"</summary>
    public static string IpListAll => Get(nameof(IpListAll));

    /// <summary>"Gaming mode"</summary>
    public static string GamingMode => Get(nameof(GamingMode));

    /// <summary>"Also unblock game traffic to the servers of the IP list."</summary>
    public static string GamingHint => Get(nameof(GamingHint));

    /// <summary>"Advanced"</summary>
    public static string Advanced => Get(nameof(Advanced));

    /// <summary>"Protocols"</summary>
    public static string Protocols => Get(nameof(Protocols));

    /// <summary>"TCP and UDP"</summary>
    public static string TcpAndUdp => Get(nameof(TcpAndUdp));

    /// <summary>"TCP ports"</summary>
    public static string TcpPorts => Get(nameof(TcpPorts));

    /// <summary>"UDP ports"</summary>
    public static string UdpPorts => Get(nameof(UdpPorts));

    /// <summary>"Save"</summary>
    public static string Save => Get(nameof(Save));

    /// <summary>"Revert"</summary>
    public static string Revert => Get(nameof(Revert));

    /// <summary>"Some entries are not valid; nothing was saved."</summary>
    public static string NotSaved => Get(nameof(NotSaved));

    /// <summary>"Settings show once the background service runs."</summary>
    public static string SettingsLater => Get(nameof(SettingsLater));

    /// <summary>"Another app (a VPN?) routes all traffic, so jink stands aside."</summary>
    public static string RoutesTaken => Get(nameof(RoutesTaken));

    /// <summary>"There is no network."</summary>
    public static string NoNetworkNow => Get(nameof(NoNetworkNow));

    /// <summary>"It did not get online in time."</summary>
    public static string NotOnline => Get(nameof(NotOnline));

    /// <summary>"The service does not run as administrator."</summary>
    public static string NotAdministrator => Get(nameof(NotAdministrator));

    /// <summary>"Another copy of jink is running."</summary>
    public static string AlreadyRunning => Get(nameof(AlreadyRunning));

    /// <summary>"jink could not create its network interface."</summary>
    public static string NoInterface => Get(nameof(NoInterface));

    /// <summary>"jink could not read or change the network routes."</summary>
    public static string Routes => Get(nameof(Routes));

    /// <summary>"jink could not see or send network traffic."</summary>
    public static string Capture => Get(nameof(Capture));

    /// <summary>"A file jink needs (WinDivert64.sys) is missing: reinstall jink."</summary>
    public static string MissingDriver => Get(nameof(MissingDriver));

    /// <summary>"Windows did not load jink's network driver (WinDivert). An antivirus may block it."</summary>
    public static string Driver => Get(nameof(Driver));

    /// <summary>"Windows did not turn on TCP timestamps, so some of this strategy's fakes do not work."</summary>
    public static string TcpTimestamps => Get(nameof(TcpTimestamps));

    /// <summary>"This strategy does not work with these settings."</summary>
    public static string BadStrategy => Get(nameof(BadStrategy));

    /// <summary>"jink could not save its settings."</summary>
    public static string NotSavedService => Get(nameof(NotSavedService));

    /// <summary>"Some connections went through unchanged."</summary>
    public static string Unchanged => Get(nameof(Unchanged));

    /// <summary>"jink could not remove all of its network routes."</summary>
    public static string RoutesLeft => Get(nameof(RoutesLeft));

    /// <summary>"jink stopped unexpectedly."</summary>
    public static string StoppedUnexpectedly => Get(nameof(StoppedUnexpectedly));

    /// <summary>"name not found"</summary>
    public static string NameNotFound => Get(nameof(NameNotFound));

    /// <summary>"unreachable"</summary>
    public static string Unreachable => Get(nameof(Unreachable));

    /// <summary>"connection cut"</summary>
    public static string ConnectionCut => Get(nameof(ConnectionCut));

    /// <summary>"wrong certificate (a block page?)"</summary>
    public static string WrongCertificate => Get(nameof(WrongCertificate));

    /// <summary>"no reply"</summary>
    public static string NoReply => Get(nameof(NoReply));

    /// <summary>"timed out"</summary>
    public static string TimedOut => Get(nameof(TimedOut));

    /// <summary>"The background service did not answer."</summary>
    public static string NoAnswer => Get(nameof(NoAnswer));

    /// <summary>"The background service answered something this app does not understand. Reinstall jink."</summary>
    public static string NotUnderstood => Get(nameof(NotUnderstood));

    /// <summary>"The service does not know the strategy {0}. Reinstall jink."</summary>
    public static string UnknownStrategy(object arg0) => Format(nameof(UnknownStrategy), arg0);

    /// <summary>"Some settings are not valid."</summary>
    public static string InvalidSettings => Get(nameof(InvalidSettings));

    /// <summary>"an empty line"</summary>
    public static string EntryEmpty => Get(nameof(EntryEmpty));

    /// <summary>"an IP address: put it under IPs"</summary>
    public static string EntryIpAddress => Get(nameof(EntryIpAddress));

    /// <summary>"a non-Latin name: enter its xn-- form"</summary>
    public static string EntryNotAscii => Get(nameof(EntryNotAscii));

    /// <summary>"the ending is missing (youtube.com, not youtube)"</summary>
    public static string EntryNoDot => Get(nameof(EntryNoDot));

    /// <summary>"not a site name"</summary>
    public static string EntryInvalidSite => Get(nameof(EntryInvalidSite));

    /// <summary>"not an IP address or network"</summary>
    public static string EntryInvalidIp => Get(nameof(EntryInvalidIp));

    /// <summary>"not a port or range (like 1024-65535)"</summary>
    public static string EntryInvalidPorts => Get(nameof(EntryInvalidPorts));
}
