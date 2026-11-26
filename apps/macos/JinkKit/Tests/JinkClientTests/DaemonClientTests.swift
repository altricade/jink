// The client against a fake daemon on a real Unix socket.

import Foundation
import JinkClient
import JinkProtocol
import Network
import Testing
import os

/// What the fake daemon does with a request line.
private enum Answer: Sendable {
    /// Sends these bytes, in separate writes.
    case chunks([String])
    /// Closes the connection.
    case close
    /// Says nothing.
    case silence
}

/// A daemon on a Unix socket that answers each request line as `answer`
/// says, and remembers what it got.
private final class FakeDaemon: Sendable {
    let path: String
    private let listener: NWListener
    private let received = OSAllocatedUnfairLock<[String]>(initialState: [])
    private let ended = OSAllocatedUnfairLock(initialState: 0)

    init(answer: @escaping @Sendable (String) -> Answer) async throws {
        // Short: Unix socket paths hold 103 bytes.
        path = "/tmp/jink-test-\(UUID().uuidString.prefix(8)).sock"
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .unix(path: path)
        listener = try NWListener(using: parameters)
        let received = received
        let ended = ended
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global())
            serve(connection, buffer: Data(), answer: answer, received: received, ended: ended)
        }
        let listener = listener
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            let once = OSAllocatedUnfairLock<CheckedContinuation<Void, any Error>?>(initialState: continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: once.withLock { $0.take() }?.resume()
                case .failed(let error): once.withLock { $0.take() }?.resume(throwing: error)
                default: break
                }
            }
            listener.start(queue: .global())
        }
    }

    var lines: [String] { received.withLock { $0 } }

    /// Connections the client has closed.
    var closed: Int { ended.withLock { $0 } }

    func stop() {
        listener.cancel()
        try? FileManager.default.removeItem(atPath: path)
    }
}

private func serve(
    _ connection: NWConnection,
    buffer: Data,
    answer: @escaping @Sendable (String) -> Answer,
    received: OSAllocatedUnfairLock<[String]>,
    ended: OSAllocatedUnfairLock<Int>
) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
        var buffer = buffer + (data ?? Data())
        while let end = buffer.firstIndex(of: 0x0A) {
            let line = String(decoding: buffer[buffer.startIndex..<end], as: UTF8.self)
            buffer = Data(buffer[buffer.index(after: end)...])
            received.withLock { $0.append(line) }
            switch answer(line) {
            case .chunks(let chunks):
                for chunk in chunks {
                    connection.send(content: Data(chunk.utf8), completion: .idempotent)
                }
            case .close:
                connection.cancel()
                return
            case .silence:
                break
            }
        }
        if isComplete || error != nil {
            ended.withLock { $0 += 1 }
            connection.cancel()
        } else {
            serve(connection, buffer: buffer, answer: answer, received: received, ended: ended)
        }
    }
}

private let off = #"{"type":"status","status":{"engine":{"state":"off"},"strategy":"alt","start_at_boot":false,"version":"0.1.0","found":null}}"#

private func offStatus() -> Message {
    .status(Status(engine: .off, strategy: "alt", startAtBoot: false, version: "0.1.0", found: nil))
}

/// Waits (up to two seconds) until `condition` holds.
private func eventually(_ condition: () -> Bool) async throws -> Bool {
    for _ in 0..<200 {
        if condition() { return true }
        try await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}

@Test func aRequestGetsItsReply() async throws {
    let daemon = try await FakeDaemon { _ in .chunks([off + "\n"]) }
    defer { daemon.stop() }
    let reply = try await DaemonClient(path: daemon.path).send(.start(strategy: "alt13"))
    #expect(reply == offStatus())
    #expect(daemon.lines == [#"{"cmd":"start","strategy":"alt13"}"#])
}

@Test func watchingFollowsUpdatesHoweverTheyArriveAndEndsWhenStopped() async throws {
    let done = #"{"type":"done"}"#
    let daemon = try await FakeDaemon { _ in
        // One message in two writes, then two in one.
        .chunks([String(off.prefix(20)), String(off.dropFirst(20)) + "\n" + done + "\n" + done + "\n"])
    }
    defer { daemon.stop() }
    var messages: [Message] = []
    for try await message in DaemonClient(path: daemon.path).watch() {
        messages.append(message)
        if messages.count == 3 { break }
    }
    #expect(messages == [offStatus(), .done, .done])
    #expect(daemon.lines == [#"{"cmd":"watch"}"#])
    // No longer watched: the connection is closed.
    #expect(try await eventually { daemon.closed == 1 })
}

@Test func withoutADaemonTheClientSaysSo() async throws {
    let client = DaemonClient(path: "/tmp/jink-test-nobody-\(UUID().uuidString.prefix(8)).sock")
    await #expect {
        _ = try await client.send(.status)
    } throws: { error in
        if case ClientError.noDaemon = error { true } else { false }
    }
    var watched = client.watch().makeAsyncIterator()
    await #expect {
        _ = try await watched.next()
    } throws: { error in
        if case ClientError.noDaemon = error { true } else { false }
    }
}

@Test func aPathTooLongForASocketIsRefused() async {
    let client = DaemonClient(path: "/tmp/" + String(repeating: "j", count: 120))
    await #expect(throws: ClientError.pathTooLong) { try await client.send(.status) }
}

@Test func aDaemonThatGoesAwayEndsTheConversation() async throws {
    let daemon = try await FakeDaemon { _ in .close }
    defer { daemon.stop() }
    let client = DaemonClient(path: daemon.path)
    await #expect(throws: ClientError.closed) { try await client.send(.status) }
    await #expect(throws: ClientError.closed) {
        for try await _ in client.watch() {}
    }
}

@Test func somethingThatIsNotAMessageIsGarbled() async throws {
    let daemon = try await FakeDaemon { _ in .chunks([#"{"type":"teapot"}"# + "\n"]) }
    defer { daemon.stop() }
    await #expect {
        _ = try await DaemonClient(path: daemon.path).send(.status)
    } throws: { error in
        if case ClientError.garbled = error { true } else { false }
    }
}

@Test func anEndlessLineIsRefused() async throws {
    let daemon = try await FakeDaemon { _ in
        .chunks(Array(repeating: String(repeating: "x", count: 64 * 1024), count: 20))
    }
    defer { daemon.stop() }
    await #expect(throws: ClientError.tooLong) {
        try await DaemonClient(path: daemon.path).send(.status)
    }
}

@Test func aRequestCanBeCancelled() async throws {
    let daemon = try await FakeDaemon { _ in .silence }
    defer { daemon.stop() }
    let client = DaemonClient(path: daemon.path)
    let request = Task { try await client.send(.status) }
    #expect(try await eventually { daemon.lines.count == 1 })
    request.cancel()
    await #expect(throws: ClientError.cancelled) { try await request.value }
}
