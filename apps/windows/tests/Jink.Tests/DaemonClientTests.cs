// The client against a fake daemon on a real named pipe (on macOS and
// Linux .NET makes named pipes from Unix sockets, so this runs anywhere).

using System.IO.Pipes;
using System.Text;
using Jink.Client;
using Jink.Protocol;

namespace Jink.Tests;

public sealed class DaemonClientTests
{
    private const string Status =
        """{"type":"status","status":{"engine":{"state":"off"},"strategy":"alt","start_at_boot":false,"version":"0.1.0","found":null}}""";

    private const string Starting =
        """{"type":"status","status":{"engine":{"state":"starting"},"strategy":"alt","start_at_boot":false,"version":"0.1.0","found":null}}""";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ARequestGetsItsReply()
    {
        var (client, daemon) = Start(async (pipe, request) =>
        {
            Assert.Equal("""{"cmd":"status"}""", request);
            await Write(pipe, Status + "\n");
        });
        var reply = await client.SendAsync(new Request.GetStatus(), Cancellation);
        Assert.IsType<Message.StatusReply>(reply);
        await daemon;
    }

    [Fact]
    public async Task WatchingFollowsUpdatesHoweverTheyArrive()
    {
        var (client, daemon) = Start(async (pipe, request) =>
        {
            Assert.Equal("""{"cmd":"watch"}""", request);
            // Two messages in one write, then one split across writes.
            await Write(pipe, Status + "\n" + Starting + "\n" + Status[..20]);
            await Task.Delay(50, Cancellation);
            await Write(pipe, Status[20..] + "\n");
        });
        var seen = new List<Message>();
        await foreach (var message in client.WatchAsync(Cancellation))
        {
            seen.Add(message);
            if (seen.Count == 3)
            {
                break;
            }
        }

        Assert.Equal(
            [typeof(Engine.Off), typeof(Engine.Starting), typeof(Engine.Off)],
            seen.Select(m => ((Message.StatusReply)m).Status.Engine.GetType()));
        await daemon;
    }

    [Fact]
    public async Task WithoutADaemonTheClientSaysSo()
    {
        var client = new DaemonClient(DaemonClient.Pipe(UniqueName()));
        var error = await Assert.ThrowsAsync<ClientException>(
            () => client.SendAsync(new Request.GetStatus(), Cancellation));
        Assert.Equal(ClientFailure.NoDaemon, error.Failure);
    }

    [Fact]
    public async Task ADaemonThatGoesAwayEndsTheConversation()
    {
        var (client, daemon) = Start((_, _) => Task.CompletedTask);
        var error = await Assert.ThrowsAsync<ClientException>(
            () => client.SendAsync(new Request.GetStatus(), Cancellation));
        Assert.Equal(ClientFailure.Closed, error.Failure);
        await daemon;
    }

    [Fact]
    public async Task SomethingThatIsNotAMessageIsGarbled()
    {
        var (client, daemon) = Start((pipe, _) => Write(pipe, """{"type":"reboot"}""" + "\n"));
        var error = await Assert.ThrowsAsync<ClientException>(
            () => client.SendAsync(new Request.GetStatus(), Cancellation));
        Assert.Equal(ClientFailure.Garbled, error.Failure);
        await daemon;
    }

    [Fact]
    public async Task AnEndlessLineIsRefused()
    {
        var (client, daemon) = Start(async (pipe, _) =>
        {
            var chunk = new string('x', 64 * 1024);
            try
            {
                for (var i = 0; i < 20; i++)
                {
                    await Write(pipe, chunk);
                }
            }
            catch (IOException)
            {
                // The client hung up, as it should.
            }
        });
        var error = await Assert.ThrowsAsync<ClientException>(
            () => client.SendAsync(new Request.GetStatus(), Cancellation));
        Assert.Equal(ClientFailure.TooLong, error.Failure);
        await daemon;
    }

    [Fact]
    public async Task ARequestCanBeCancelled()
    {
        using var stop = new CancellationTokenSource();
        var (client, daemon) = Start(async (_, _) => await Task.Delay(TimeSpan.FromSeconds(10), stop.Token)
            .ContinueWith(_ => { }, TaskScheduler.Default));
        var asked = client.SendAsync(new Request.GetStatus(), stop.Token);
        await Task.Delay(100, Cancellation);
        await stop.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => asked);
        await daemon;
    }

    /// <summary>A client, and a fake daemon that takes one connection, reads
    /// its request line and then does <paramref name="serve"/>.</summary>
    private static (DaemonClient Client, Task Daemon) Start(Func<NamedPipeServerStream, string, Task> serve)
    {
        var name = UniqueName();
        // The client waits for the pipe to appear (up to 2 s).
        var daemon = Task.Run(async () =>
        {
            await using var pipe = new NamedPipeServerStream(
                name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            await pipe.WaitForConnectionAsync(Cancellation);
            var request = await ReadLine(pipe);
            await serve(pipe, request);
        });
        return (new DaemonClient(DaemonClient.Pipe(name)), daemon);
    }

    private static string UniqueName() => "jink-test-" + Guid.NewGuid().ToString("N")[..12];

    private static async Task<string> ReadLine(Stream pipe)
    {
        var line = new List<byte>();
        var one = new byte[1];
        while (await pipe.ReadAsync(one, Cancellation) == 1 && one[0] != (byte)'\n')
        {
            line.Add(one[0]);
        }

        return Encoding.UTF8.GetString([.. line]);
    }

    private static async Task Write(Stream pipe, string text)
    {
        await pipe.WriteAsync(Encoding.UTF8.GetBytes(text), Cancellation);
        await pipe.FlushAsync(Cancellation);
    }
}
