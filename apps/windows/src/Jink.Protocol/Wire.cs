// The JSON of the control channel, as docs/control-protocol.md describes it:
// tagged objects ("type", "state", "result", "code", "cmd") read and written
// by hand, so that anything this app does not know is an error, never a
// guess.

using System.Text.Json;

namespace Jink.Protocol;

/// <summary>A line from the daemon that is not a message this app
/// knows.</summary>
public sealed class WireException : Exception
{
    /// <summary>Why the line is not understood.</summary>
    public WireException(string message)
        : base(message)
    {
    }

    /// <summary>Why the line is not understood, and the JSON error.</summary>
    public WireException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>An unexplained wire error.</summary>
    public WireException()
    {
    }
}

/// <summary>Reads messages and writes requests.</summary>
public static class Wire
{
    /// <summary>The message in one line (without its newline).</summary>
    /// <exception cref="WireException">If it is not a message this app
    /// knows.</exception>
    public static Message Decode(ReadOnlySpan<byte> line)
    {
        try
        {
            var reader = new Utf8JsonReader(line);
            using var document = JsonDocument.ParseValue(ref reader);
            return DecodeMessage(document.RootElement);
        }
        catch (JsonException e)
        {
            throw new WireException("not JSON", e);
        }
        catch (InvalidOperationException e)
        {
            // A value of another JSON kind than expected.
            throw new WireException("a value of the wrong kind", e);
        }
    }

    /// <summary>The line for <paramref name="request"/> (UTF-8, without its
    /// newline).</summary>
    public static byte[] Encode(Request request)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            switch (request)
            {
                case Request.GetStatus:
                    writer.WriteString("cmd", "status");
                    break;
                case Request.GetStrategies:
                    writer.WriteString("cmd", "strategies");
                    break;
                case Request.Start start:
                    writer.WriteString("cmd", "start");
                    if (start.Strategy is { } strategy)
                    {
                        writer.WriteString("strategy", strategy);
                    }

                    break;
                case Request.Stop:
                    writer.WriteString("cmd", "stop");
                    break;
                case Request.GetSettings:
                    writer.WriteString("cmd", "settings");
                    break;
                case Request.UpdateSettings update:
                    writer.WriteString("cmd", "update_settings");
                    writer.WritePropertyName("settings");
                    WriteSettings(writer, update.Settings);
                    break;
                case Request.SetStartAtBoot boot:
                    writer.WriteString("cmd", "set_start_at_boot");
                    writer.WriteBoolean("on", boot.On);
                    break;
                case Request.Find:
                    writer.WriteString("cmd", "find");
                    break;
                case Request.CancelFind:
                    writer.WriteString("cmd", "cancel_find");
                    break;
                case Request.Watch:
                    writer.WriteString("cmd", "watch");
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(request), request, "an unknown request");
            }

            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static void WriteSettings(Utf8JsonWriter writer, Settings settings)
    {
        writer.WriteStartObject();
        WriteList(writer, "my_sites", settings.MySites);
        WriteList(writer, "my_ips", settings.MyIps);
        WriteList(writer, "excluded_sites", settings.ExcludedSites);
        WriteList(writer, "excluded_ips", settings.ExcludedIps);
        writer.WriteStartObject("gaming");
        writer.WriteString("mode", settings.Gaming.Mode switch
        {
            GamingMode.Off => "off",
            GamingMode.Tcp => "tcp",
            GamingMode.Udp => "udp",
            GamingMode.Both => "both",
            _ => throw new ArgumentOutOfRangeException(nameof(settings), settings.Gaming.Mode, "an unknown gaming mode"),
        });
        writer.WriteString("tcp_ports", settings.Gaming.TcpPorts);
        writer.WriteString("udp_ports", settings.Gaming.UdpPorts);
        writer.WriteEndObject();
        writer.WriteString("ip_list", settings.IpList switch
        {
            IpList.Off => "off",
            IpList.BuiltIn => "built_in",
            IpList.All => "all",
            _ => throw new ArgumentOutOfRangeException(nameof(settings), settings.IpList, "an unknown IP list"),
        });
        writer.WriteEndObject();
    }

    private static void WriteList(Utf8JsonWriter writer, string name, Items<string> items)
    {
        writer.WriteStartArray(name);
        foreach (var item in items)
        {
            writer.WriteStringValue(item);
        }

        writer.WriteEndArray();
    }

    private static Message DecodeMessage(JsonElement json) => Text(json, "type") switch
    {
        "status" => new Message.StatusReply(DecodeStatus(Field(json, "status"))),
        "strategies" => new Message.StrategiesReply(List(Field(json, "strategies"), DecodeStrategy)),
        "settings" => new Message.SettingsReply(DecodeSettings(Field(json, "settings"))),
        "done" => new Message.Done(),
        "error" => new Message.Error(DecodeFailure(Field(json, "error"))),
        "notice" => new Message.Notice(DecodeProblem(Field(json, "notice"))),
        var other => throw new WireException($"an unknown message type {other}"),
    };

    private static Status DecodeStatus(JsonElement json) => new(
        DecodeEngine(Field(json, "engine")),
        Text(json, "strategy"),
        Field(json, "start_at_boot").GetBoolean(),
        Text(json, "version"),
        Optional(json, "found", DecodeFound));

    private static Engine DecodeEngine(JsonElement json) => Text(json, "state") switch
    {
        "off" => new Engine.Off(),
        "starting" => new Engine.Starting(),
        "on" => new Engine.On(DecodeNetwork(Field(json, "network"))),
        "failed" => new Engine.Failed(DecodeProblem(Field(json, "problem"))),
        "finding" => new Engine.Finding(
            Field(json, "step").GetInt32(),
            Field(json, "of").GetInt32(),
            Optional(json, "strategy", e => e.GetString())),
        var other => throw new WireException($"an unknown engine state {other}"),
    };

    private static Network DecodeNetwork(JsonElement json) => Text(json, "state") switch
    {
        "checking" => new Network.Checking(),
        "online" => new Network.Online(Text(json, "uplink"), Field(json, "ipv6").GetBoolean()),
        "active" => new Network.Active(),
        "offline" => new Network.Offline(),
        "bypassed" => new Network.Bypassed(DecodeProblem(Field(json, "problem"))),
        var other => throw new WireException($"an unknown network state {other}"),
    };

    private static Problem DecodeProblem(JsonElement json) => new(Text(json, "code"), Text(json, "detail"));

    private static StrategyInfo DecodeStrategy(JsonElement json) => new(
        Text(json, "id"),
        Text(json, "name"),
        Optional(json, "variant_of", e => e.GetString()),
        Text(json, "support") switch
        {
            "full" => Support.Full,
            "partial" => Support.Partial,
            var other => throw new WireException($"an unknown support {other}"),
        });

    private static Failure DecodeFailure(JsonElement json) => Text(json, "code") switch
    {
        "bad_request" => new Failure.BadRequest(Text(json, "detail")),
        "unknown_strategy" => new Failure.UnknownStrategy(Text(json, "strategy")),
        "invalid_settings" => new Failure.InvalidSettings(List(Field(json, "problems"), DecodeSettingsProblem)),
        "failed" => new Failure.Failed(Text(json, "detail")),
        var other => throw new WireException($"an unknown error code {other}"),
    };

    private static SettingsProblem DecodeSettingsProblem(JsonElement json) => new(
        Text(json, "field"),
        Optional<int?>(json, "index", e => e.GetInt32()),
        Text(json, "code"));

    private static Settings DecodeSettings(JsonElement json)
    {
        var gaming = Field(json, "gaming");
        return new Settings(
            List(Field(json, "my_sites"), Required),
            List(Field(json, "my_ips"), Required),
            List(Field(json, "excluded_sites"), Required),
            List(Field(json, "excluded_ips"), Required),
            new Gaming(
                Text(gaming, "mode") switch
                {
                    "off" => GamingMode.Off,
                    "tcp" => GamingMode.Tcp,
                    "udp" => GamingMode.Udp,
                    "both" => GamingMode.Both,
                    var other => throw new WireException($"an unknown gaming mode {other}"),
                },
                Text(gaming, "tcp_ports"),
                Text(gaming, "udp_ports")),
            Text(json, "ip_list") switch
            {
                "off" => IpList.Off,
                "built_in" => IpList.BuiltIn,
                "all" => IpList.All,
                var other => throw new WireException($"an unknown IP list {other}"),
            });
    }

    private static Found DecodeFound(JsonElement json) => new(
        Text(json, "result") switch
        {
            "kept" => new FindResult.Kept(Text(json, "strategy")),
            "nothing_blocked" => new FindResult.NothingBlocked(),
            "none_helped" => new FindResult.NoneHelped(),
            "no_network" => new FindResult.NoNetwork(),
            var other => throw new WireException($"an unknown finding result {other}"),
        },
        Field(json, "checks").GetInt32(),
        DecodeChecks(Field(json, "without")),
        List(Field(json, "tried"), DecodeTried));

    private static Checks DecodeChecks(JsonElement json) =>
        new(Field(json, "passed").GetInt32(), List(Field(json, "failed"), DecodeFailedCheck));

    private static FailedCheck DecodeFailedCheck(JsonElement json) => new(
        Text(json, "host"),
        Text(json, "tls") switch
        {
            "1.2" => Tls.V12,
            "1.3" => Tls.V13,
            var other => throw new WireException($"an unknown TLS version {other}"),
        },
        Text(json, "outcome") switch
        {
            "no_address" => Outcome.NoAddress,
            "unreachable" => Outcome.Unreachable,
            "cut" => Outcome.Cut,
            "certificate" => Outcome.Certificate,
            "no_reply" => Outcome.NoReply,
            "timed_out" => Outcome.TimedOut,
            var other => throw new WireException($"an unknown check outcome {other}"),
        });

    /// <summary>A strategy tried: its checks are flattened into it.</summary>
    private static Tried DecodeTried(JsonElement json) => new(
        Text(json, "strategy"),
        DecodeChecks(json),
        Optional(json, "problem", DecodeProblem));

    private static JsonElement Field(JsonElement json, string name) =>
        json.ValueKind == JsonValueKind.Object && json.TryGetProperty(name, out var value)
            ? value
            : throw new WireException($"no {name}");

    private static string Text(JsonElement json, string name) => Required(Field(json, name));

    private static string Required(JsonElement json) =>
        json.GetString() ?? throw new WireException("null where text is required");

    /// <summary>A field that is null (or absent) when there is none.</summary>
    private static T? Optional<T>(JsonElement json, string name, Func<JsonElement, T> decode) =>
        json.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? decode(value)
            : default;

    private static Items<T> List<T>(JsonElement json, Func<JsonElement, T> decode) =>
        json.ValueKind == JsonValueKind.Array
            ? new Items<T>(json.EnumerateArray().Select(decode))
            : throw new WireException("not a list");
}
