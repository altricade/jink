// The connection to the jink daemon: its Unix socket, one JSON request per
// line and one reply per request; after `watch`, a stream of updates.

import Foundation
public import JinkProtocol
import Network
import os

/// Why talking to the daemon failed.
public enum ClientError: Error, Equatable, Sendable {
    /// No daemon answers (the service is not installed or not running);
    /// `detail` is the system's text.
    case noDaemon(detail: String)
    /// The daemon closed the connection (it is stopping, usually).
    case closed
    /// The daemon sent something this app does not understand (a different
    /// version, usually); `detail` says what.
    case garbled(detail: String)
    /// A line longer than any message.
    case tooLong
    /// The socket's path does not fit a Unix socket address.
    case pathTooLong
    case cancelled
}

/// Talks to the daemon at `path`.
public struct DaemonClient: Sendable {
    /// The daemon's socket on macOS.
    public static let socket = "/var/run/jink.sock"

    public let path: String

    public init(path: String = DaemonClient.socket) {
        self.path = path
    }

    /// The daemon's answer to `request`, over a connection of its own.
    public func send(_ request: Request) async throws(ClientError) -> Message {
        try await mapped {
            let connection = try LineConnection(path: path)
            defer { connection.close() }
            try await connection.open()
            try await connection.send(Wire.line(request))
            return try Wire.message(await connection.line())
        }
    }

    /// The status now and at every change, and every notice, until the
    /// stream is no longer iterated; it ends with a `ClientError` when the
    /// daemon cannot be reached or goes away.
    public func watch() -> AsyncThrowingStream<Message, any Error> {
        AsyncThrowingStream { continuation in
            let path = path
            let task = Task {
                do throws(ClientError) {
                    try await mapped {
                        let connection = try LineConnection(path: path)
                        defer { connection.close() }
                        try await connection.open()
                        try await connection.send(Wire.line(.watch))
                        while true {
                            continuation.yield(try Wire.message(await connection.line()))
                        }
                    }
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

/// `work`'s result, with every failure as a `ClientError`.
private func mapped<T>(_ work: () async throws -> T) async throws(ClientError) -> T {
    do {
        return try await work()
    } catch let error as ClientError {
        throw error
    } catch is CancellationError {
        throw .cancelled
    } catch let error as DecodingError {
        throw .garbled(detail: String(describing: error))
    } catch {
        throw .garbled(detail: error.localizedDescription)
    }
}

/// One connection, read line by line.
private actor LineConnection {
    /// The longest line read (messages are far shorter).
    private static let maxLine = 1 << 20
    /// `sockaddr_un.sun_path` holds 104 bytes with the final zero; a longer
    /// path makes Network.framework stop the process.
    private static let maxPath = 103

    private let connection: NWConnection
    private var buffer = Data()

    init(path: String) throws(ClientError) {
        guard path.utf8.count <= Self.maxPath else { throw .pathTooLong }
        connection = NWConnection(to: .unix(path: path), using: .tcp)
    }

    nonisolated func close() {
        connection.cancel()
    }

    func open() async throws {
        let connection = connection
        try await cancellable {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let once = Once(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.resume(with: .success(()))
                    // Waiting means it would retry later; the app retries
                    // itself, and says meanwhile that there is no daemon.
                    case .waiting(let error), .failed(let error):
                        once.resume(with: .failure(ClientError.noDaemon(detail: error.localizedDescription)))
                    case .cancelled: once.resume(with: .failure(CancellationError()))
                    case .setup, .preparing: break
                    @unknown default: break
                    }
                }
                connection.start(queue: .global())
            }
        }
    }

    func send(_ data: Data) async throws {
        let connection = connection
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: data,
                completion: .contentProcessed { error in
                    continuation.resume(with: error.map { _ in .failure(ClientError.closed) } ?? .success(()))
                }
            )
        }
    }

    /// The next line, without its newline.
    func line() async throws -> Data {
        while true {
            if let end = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<end]
                buffer = Data(buffer[buffer.index(after: end)...])
                return Data(line)
            }
            guard buffer.count <= Self.maxLine else { throw ClientError.tooLong }
            buffer.append(try await receive())
        }
    }

    /// The next bytes; `closed` at the end of the stream.
    private func receive() async throws -> Data {
        let connection = connection
        return try await cancellable {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, ended, error in
                    if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if error != nil || ended {
                        continuation.resume(throwing: ClientError.closed)
                    } else {
                        continuation.resume(returning: Data())
                    }
                }
            }
        }
    }

    /// `work`, ended by cancelling the connection when the task is
    /// cancelled (and then failing with `CancellationError`).
    private func cancellable<T: Sendable>(_ work: () async throws -> T) async throws -> T {
        let connection = connection
        do {
            return try await withTaskCancellationHandler(operation: work) {
                connection.cancel()
            }
        } catch {
            try Task.checkCancellation()
            throw error
        }
    }
}

/// Resumes a continuation the first time only (connection states can
/// repeat).
private final class Once<T: Sendable>: Sendable {
    private let continuation: OSAllocatedUnfairLock<CheckedContinuation<T, any Error>?>

    init(_ continuation: CheckedContinuation<T, any Error>) {
        self.continuation = OSAllocatedUnfairLock(initialState: continuation)
    }

    func resume(with result: Result<T, any Error>) {
        continuation.withLock { $0.take() }?.resume(with: result)
    }
}
