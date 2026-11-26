// What the tests share: the repository's contract folder, a UI thread to
// run the app model on (as the app does), waiting for a condition, and a
// fake daemon.

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Jink.Client;
using Jink.Protocol;

namespace Jink.Tests;

/// <summary>Paths in the repository.</summary>
internal static class Repository
{
    /// <summary>The repository's <c>contract</c> folder: found upwards from
    /// this source file.</summary>
    public static string Contract([CallerFilePath] string here = "")
    {
        var folder = new DirectoryInfo(Path.GetDirectoryName(here) ?? ".");
        while (folder is not null && !File.Exists(Path.Combine(folder.FullName, "Cargo.toml")))
        {
            folder = folder.Parent;
        }

        return folder is null
            ? throw new DirectoryNotFoundException("no repository above " + here)
            : Path.Combine(folder.FullName, "contract");
    }
}

/// <summary>One thread with a message loop: what the app's UI thread is to
/// the app model. Work posted to it runs there in order, and its awaits
/// resume there.</summary>
internal sealed class UiThread : SynchronizationContext, IDisposable
{
    private readonly BlockingCollection<(SendOrPostCallback Work, object? State)> queue = [];
    private readonly Thread thread;

    public UiThread()
    {
        thread = new Thread(Loop) { IsBackground = true, Name = "UI" };
        thread.Start();
    }

    public override void Post(SendOrPostCallback d, object? state) => queue.Add((d, state));

    public override void Send(SendOrPostCallback d, object? state) =>
        throw new NotSupportedException("the UI thread is only posted to");

    /// <summary>Runs <paramref name="work"/> on the UI thread.</summary>
    public Task<T> Run<T>(Func<Task<T>> work)
    {
        var done = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        Post(_ => work().ContinueWith(
            ended =>
            {
                if (ended.Exception is { } e)
                {
                    done.SetException(e.InnerExceptions);
                }
                else if (ended.IsCanceled)
                {
                    done.SetCanceled();
                }
                else
                {
                    done.SetResult(ended.Result);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default), null);
        return done.Task;
    }

    /// <summary>Runs <paramref name="work"/> on the UI thread.</summary>
    public Task Run(Func<Task> work) => Run(async () =>
    {
        await work();
        return true;
    });

    /// <summary>Reads <paramref name="read"/> on the UI thread.</summary>
    public Task<T> Read<T>(Func<T> read) => Run(() => Task.FromResult(read()));

    /// <summary>Whether <paramref name="condition"/> holds on the UI thread
    /// within a few seconds.</summary>
    public async Task<bool> Eventually(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (await Read(condition))
            {
                return true;
            }

            await Task.Delay(10);
        }

        return false;
    }

    public void Dispose()
    {
        queue.CompleteAdding();
        thread.Join();
        queue.Dispose();
    }

    private void Loop()
    {
        SetSynchronizationContext(this);
        foreach (var (work, state) in queue.GetConsumingEnumerable())
        {
            work(state);
        }
    }
}

/// <summary>A daemon the test plays: it answers requests as told, and
/// streams what the test pushes to whoever watches.</summary>
internal sealed class FakeDaemon : IDaemonLink
{
    private readonly ConcurrentQueue<Request> sent = new();
    private Channel<Message>? watching;
    private Func<Request, Message> answer = _ => new Message.Done();
    private volatile bool down;
    private int watches;

    /// <summary>Every request sent, in order.</summary>
    public IReadOnlyList<Request> Sent => [.. sent];

    /// <summary>How many times the app started watching.</summary>
    public int Watches => Volatile.Read(ref watches);

    /// <summary>While down, connecting fails as without a daemon.</summary>
    public bool Down
    {
        get => down;
        set => down = value;
    }

    /// <summary>Answers each request with <paramref name="reply"/>.</summary>
    public void Answer(Func<Request, Message> reply) => answer = reply;

    /// <summary>Sends <paramref name="message"/> to the app watching.</summary>
    public void Push(Message message)
    {
        if (watching is null || !watching.Writer.TryWrite(message))
        {
            throw new InvalidOperationException("nobody watches");
        }
    }

    /// <summary>Ends the watch as a daemon that goes away does.</summary>
    public void HangUp() =>
        watching?.Writer.TryComplete(new ClientException(ClientFailure.Closed, "the daemon closed the connection"));

    public Task<Message> SendAsync(Request request, CancellationToken cancellation)
    {
        if (Down)
        {
            throw new ClientException(ClientFailure.NoDaemon, "no pipe");
        }

        sent.Enqueue(request);
        return Task.FromResult(answer(request));
    }

    public async IAsyncEnumerable<Message> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellation)
    {
        Interlocked.Increment(ref watches);
        if (Down)
        {
            throw new ClientException(ClientFailure.NoDaemon, "no pipe");
        }

        var channel = Channel.CreateUnbounded<Message>();
        watching = channel;
        await foreach (var message in channel.Reader.ReadAllAsync(cancellation))
        {
            yield return message;
        }
    }
}
