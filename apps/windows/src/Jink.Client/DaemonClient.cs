// The connection to the jink daemon: its named pipe, one JSON request per
// line and one reply per request; after watch, a stream of updates.

using System.Buffers;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using Jink.Protocol;

namespace Jink.Client;

/// <summary>Why talking to the daemon failed.</summary>
public enum ClientFailure
{
    /// <summary>No daemon answers (the service is not installed or not
    /// running).</summary>
    NoDaemon,

    /// <summary>The daemon closed the connection (it is stopping,
    /// usually).</summary>
    Closed,

    /// <summary>The daemon sent something this app does not understand (a
    /// different version, usually).</summary>
    Garbled,

    /// <summary>A line longer than any message.</summary>
    TooLong,
}

/// <summary>Talking to the daemon failed; <see cref="Failure"/> says how and
/// the message gives the system's text.</summary>
public sealed class ClientException : Exception
{
    /// <summary>A failure of kind <paramref name="failure"/>.</summary>
    public ClientException(ClientFailure failure, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Failure = failure;
    }

    /// <summary>A failure of unknown kind (treated as no daemon).</summary>
    public ClientException()
        : this(ClientFailure.NoDaemon, "no daemon")
    {
    }

    /// <summary>A failure of unknown kind (treated as no daemon).</summary>
    public ClientException(string message)
        : this(ClientFailure.NoDaemon, message)
    {
    }

    /// <summary>A failure of unknown kind (treated as no daemon).</summary>
    public ClientException(string message, Exception innerException)
        : this(ClientFailure.NoDaemon, message, innerException)
    {
    }

    /// <summary>How it failed.</summary>
    public ClientFailure Failure { get; }
}

/// <summary>What the app talks to: the daemon (<see cref="DaemonClient"/>),
/// or a fake in tests.</summary>
public interface IDaemonLink
{
    /// <summary>The daemon's answer to <paramref name="request"/>.</summary>
    /// <exception cref="ClientException">If it could not be asked.</exception>
    Task<Message> SendAsync(Request request, CancellationToken cancellation);

    /// <summary>The status now and at every change, and every notice, until
    /// cancelled; it ends with a <see cref="ClientException"/> when the
    /// daemon cannot be reached or goes away.</summary>
    IAsyncEnumerable<Message> WatchAsync(CancellationToken cancellation);
}

/// <summary>Talks to the daemon through connections that
/// <c>connect</c> opens (the daemon's pipe, unless a test says
/// otherwise).</summary>
public sealed class DaemonClient : IDaemonLink
{
    /// <summary>The daemon's pipe: <c>\\.\pipe\jink</c>.</summary>
    public const string PipeName = "jink";

    /// <summary>The longest line read (messages are far shorter).</summary>
    private const int MaxLine = 1 << 20;

    /// <summary>How long to wait for the pipe to take a connection.</summary>
    private static readonly TimeSpan ConnectLimit = TimeSpan.FromSeconds(2);

    private readonly Func<CancellationToken, ValueTask<Stream>> connect;

    /// <summary>Talks to the daemon's pipe.</summary>
    public DaemonClient()
        : this(Pipe(PipeName))
    {
    }

    /// <summary>Talks to whatever <paramref name="connect"/> opens.</summary>
    public DaemonClient(Func<CancellationToken, ValueTask<Stream>> connect)
    {
        this.connect = connect;
    }

    /// <summary>Opens the named pipe <paramref name="name"/> on this computer.
    /// On Windows it asks for no more than the daemon lets users do: read
    /// and write data (not create instances of the pipe).</summary>
    public static Func<CancellationToken, ValueTask<Stream>> Pipe(string name) => async cancellation =>
    {
        var pipe = OperatingSystem.IsWindows()
            ? new NamedPipeClientStream(
                ".",
                name,
                PipeAccessRights.ReadData | PipeAccessRights.WriteData
                    | PipeAccessRights.ReadAttributes | PipeAccessRights.WriteAttributes
                    | PipeAccessRights.ReadExtendedAttributes | PipeAccessRights.WriteExtendedAttributes
                    | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification,
                HandleInheritability.None)
            : new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(ConnectLimit, cancellation).ConfigureAwait(false);
            return pipe;
        }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new ClientException(ClientFailure.NoDaemon, e.Message, e);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    };

    /// <inheritdoc/>
    public async Task<Message> SendAsync(Request request, CancellationToken cancellation)
    {
        var stream = await connect(cancellation).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            var lines = new LineReader(stream);
            await WriteAsync(stream, request, cancellation).ConfigureAwait(false);
            return await lines.NextAsync(cancellation).ConfigureAwait(false);
        }
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<Message> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellation)
    {
        var stream = await connect(cancellation).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            var lines = new LineReader(stream);
            await WriteAsync(stream, new Request.Watch(), cancellation).ConfigureAwait(false);
            while (true)
            {
                yield return await lines.NextAsync(cancellation).ConfigureAwait(false);
            }
        }
    }

    private static async Task WriteAsync(Stream stream, Request request, CancellationToken cancellation)
    {
        byte[] line = [.. Wire.Encode(request), (byte)'\n'];
        try
        {
            await stream.WriteAsync(line, cancellation).ConfigureAwait(false);
            await stream.FlushAsync(cancellation).ConfigureAwait(false);
        }
        catch (IOException e)
        {
            throw new ClientException(ClientFailure.Closed, e.Message, e);
        }
    }

    /// <summary>A connection read line by line.</summary>
    private sealed class LineReader(Stream stream)
    {
        private readonly ArrayBufferWriter<byte> buffer = new();
        private int start;

        /// <summary>The next message.</summary>
        public async Task<Message> NextAsync(CancellationToken cancellation)
        {
            while (true)
            {
                var unread = buffer.WrittenSpan[start..];
                var end = unread.IndexOf((byte)'\n');
                if (end >= 0)
                {
                    var message = Decode(unread[..end]);
                    start += end + 1;
                    return message;
                }

                if (unread.Length > MaxLine)
                {
                    throw new ClientException(ClientFailure.TooLong, $"a line longer than {MaxLine} bytes");
                }

                Compact();
                var read = await ReadAsync(cancellation).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new ClientException(ClientFailure.Closed, "the daemon closed the connection");
                }
            }
        }

        private static Message Decode(ReadOnlySpan<byte> line)
        {
            try
            {
                return Wire.Decode(line);
            }
            catch (WireException e)
            {
                throw new ClientException(ClientFailure.Garbled, e.Message, e);
            }
        }

        /// <summary>Drops the lines already read.</summary>
        private void Compact()
        {
            if (start == 0)
            {
                return;
            }

            var rest = buffer.WrittenSpan[start..].ToArray();
            buffer.ResetWrittenCount();
            buffer.Write(rest);
            start = 0;
        }

        private async Task<int> ReadAsync(CancellationToken cancellation)
        {
            var memory = buffer.GetMemory(64 * 1024);
            try
            {
                var read = await stream.ReadAsync(memory, cancellation).ConfigureAwait(false);
                buffer.Advance(read);
                return read;
            }
            catch (IOException e)
            {
                throw new ClientException(ClientFailure.Closed, e.Message, e);
            }
        }
    }
}
