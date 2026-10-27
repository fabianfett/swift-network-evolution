//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork

#if IMPORT_CRYPTO && !NETWORK_NO_SWIFT_QUIC

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

/// Two state machines connected back to back, driven in lockstep with a manual clock.
@available(Network 0.1.0, *)
struct LockstepPair: ~Copyable {
    var client: QUICConnectionCore
    var server: QUICConnectionCore?
    var now = NetworkClock.Instant(milliseconds: 1_000)
    let serverConfiguration: QUICConnectionCore.Configuration
    /// Datagrams in flight, per direction.
    var toServer: [[UInt8]] = []
    var toClient: [[UInt8]] = []
    var clientEvents: [QUICConnectionCore.Event] = []
    var serverEvents: [QUICConnectionCore.Event] = []
    /// The largest datagram the link carries in ``exchange(rounds:drop:)``; larger ones are lost.
    var linkMaxDatagramSize = Int.max
    /// The sizes of the datagrams the link dropped for being too large, per direction.
    var droppedForSize: (toServer: [Int], toClient: [Int]) = ([], [])

    init(
        clientConfiguration: QUICConnectionCore.Configuration? = nil,
        serverConfiguration: QUICConnectionCore.Configuration? = nil,
        clientConnectionIDLength: Int = 8,
        clientTLSOptions: SwiftTLSProtocol.Options? = nil,
        serverTLSOptions: SwiftTLSProtocol.Options? = nil
    ) {
        // Without TLS options of their own, both sides use a raw public key.
        let serverKey = P256.Signing.PrivateKey()
        var clientTLS = SwiftTLSProtocol.Options()
        clientTLS.applicationProtocols = ["qsm-test"]
        clientTLS.serverName = "quic-test.local"
        clientTLS.trustedRawPublicKeyCertificates = [[UInt8](serverKey.publicKey.derRepresentation)]
        var serverTLS = SwiftTLSProtocol.Options()
        serverTLS.applicationProtocols = ["qsm-test"]
        serverTLS.rawPrivateKey = [UInt8](serverKey.rawRepresentation)
        if let clientTLSOptions { clientTLS = clientTLSOptions }
        if let serverTLSOptions { serverTLS = serverTLSOptions }

        var clientConfiguration = clientConfiguration ?? QUICConnectionCore.Configuration(tlsOptions: clientTLS)
        clientConfiguration.tlsOptions = clientTLS
        var serverConfiguration = serverConfiguration ?? QUICConnectionCore.Configuration(tlsOptions: serverTLS)
        serverConfiguration.tlsOptions = serverTLS
        self.serverConfiguration = serverConfiguration
        self.client = QUICConnectionCore(
            clientWith: clientConfiguration,
            localConnectionID: QUICConnectionID(clientConnectionIDLength),
            destinationConnectionID: QUICConnectionID(8),
            now: self.now
        )
    }

    static func drain(_ machine: inout QUICConnectionCore, now: NetworkClock.Instant) -> [[UInt8]] {
        var datagrams: [[UInt8]] = []
        var buffer = [UInt8](repeating: 0, count: 1500)
        while true {
            if machine.datagramCapacity > buffer.count {
                // A PMTUD probe may be larger.
                buffer = [UInt8](repeating: 0, count: machine.datagramCapacity)
            }
            var span = buffer.mutableSpan
            guard let length = machine.send(into: &span, now: now) else { break }
            datagrams.append(Array(buffer[0..<length]))
            if datagrams.count > 1000 { break }
        }
        return datagrams
    }

    static func events(_ machine: inout QUICConnectionCore) -> [QUICConnectionCore.Event] {
        var events: [QUICConnectionCore.Event] = []
        while let event = machine.nextEvent() {
            events.append(event)
        }
        return events
    }

    /// Reads the connection IDs from the header of a client Initial.
    static func connectionIDs(ofInitial datagram: [UInt8]) -> (destination: QUICConnectionID, source: QUICConnectionID)
    {
        let dcidLength = Int(datagram[5])
        let dcid = QUICConnectionID(Array(datagram[6..<(6 + dcidLength)]))!
        let scidLength = Int(datagram[6 + dcidLength])
        let scid = QUICConnectionID(Array(datagram[(7 + dcidLength)..<(7 + dcidLength + scidLength)]))!
        return (dcid, scid)
    }

    /// Exchanges datagrams until neither side has anything to send. `drop` decides per datagram
    /// whether it gets lost.
    mutating func exchange(rounds: Int = 50, drop: (_ toServer: Bool, _ index: Int) -> Bool = { _, _ in false }) {
        var index = 0
        for _ in 0..<rounds {
            self.toServer += Self.drain(&self.client, now: self.now)
            if self.server == nil, let first = self.toServer.first {
                let ids = Self.connectionIDs(ofInitial: first)
                self.server = QUICConnectionCore(
                    serverWith: self.serverConfiguration,
                    localConnectionID: QUICConnectionID(8),
                    originalDestinationConnectionID: ids.destination,
                    peerConnectionID: ids.source,
                    now: self.now
                )
            }
            guard var server = self.server.take() else { return }
            for var datagram in self.toServer {
                defer { index += 1 }
                if drop(true, index) { continue }
                guard datagram.count <= self.linkMaxDatagramSize else {
                    self.droppedForSize.toServer.append(datagram.count)
                    continue
                }
                var span = datagram.mutableSpan
                server.receive(&span, now: self.now)
            }
            self.toServer.removeAll()
            self.serverEvents += Self.events(&server)
            self.toClient += Self.drain(&server, now: self.now)
            for var datagram in self.toClient {
                defer { index += 1 }
                if drop(false, index) { continue }
                guard datagram.count <= self.linkMaxDatagramSize else {
                    self.droppedForSize.toClient.append(datagram.count)
                    continue
                }
                var span = datagram.mutableSpan
                self.client.receive(&span, now: self.now)
            }
            self.toClient.removeAll()
            self.clientEvents += Self.events(&self.client)
            let clientQuiet = Self.drainCount(&self.client, now: self.now, into: &self.toServer) == 0
            self.server = consume server
            if clientQuiet && self.toServer.isEmpty {
                // Nothing in flight; advance to the next timer, if any is close.
                return
            }
        }
    }

    private static func drainCount(
        _ machine: inout QUICConnectionCore,
        now: NetworkClock.Instant,
        into queue: inout [[UInt8]]
    ) -> Int {
        let datagrams = Self.drain(&machine, now: now)
        queue += datagrams
        return datagrams.count
    }

    /// A datagram as the network carries it: on a path, with the ECN codepoint of its IP header.
    struct NetworkDatagram {
        var path: CorePathID
        var ecn: IPProtocol.ECN
        var bytes: [UInt8]
    }

    /// Everything `machine` has to send, the probes for other paths first, each with its
    /// codepoint.
    static func drainWithECN(_ machine: inout QUICConnectionCore, now: NetworkClock.Instant) -> [NetworkDatagram] {
        var datagrams: [NetworkDatagram] = []
        var buffer = [UInt8](repeating: 0, count: 1500)
        while datagrams.count < 1000 {
            let path = machine.pathWithProbeToSend ?? machine.activePathID
            var span = buffer.mutableSpan
            guard let length = machine.send(into: &span, on: path, now: now) else { break }
            datagrams.append(
                NetworkDatagram(path: path, ecn: machine.lastDatagramECN, bytes: Array(buffer[0..<length]))
            )
        }
        return datagrams
    }

    /// Like ``exchange(rounds:drop:)``, but each datagram keeps its path and ECN codepoint.
    /// `network` sees every datagram and may change its path and codepoint, or drop it by
    /// returning `false`.
    mutating func exchangeWithECN(
        rounds: Int = 50,
        network: (_ toServer: Bool, _ datagram: inout NetworkDatagram) -> Bool = { _, _ in true }
    ) {
        for _ in 0..<rounds {
            let fromClient = Self.drainWithECN(&self.client, now: self.now)
            if self.server == nil, let first = fromClient.first {
                let ids = Self.connectionIDs(ofInitial: first.bytes)
                self.server = QUICConnectionCore(
                    serverWith: self.serverConfiguration,
                    localConnectionID: QUICConnectionID(8),
                    originalDestinationConnectionID: ids.destination,
                    peerConnectionID: ids.source,
                    now: self.now
                )
            }
            guard var server = self.server.take() else { return }
            for var datagram in fromClient {
                guard network(true, &datagram) else { continue }
                let (path, ecn) = (datagram.path, datagram.ecn)
                var span = datagram.bytes.mutableSpan
                server.receive(&span, on: path, ecn: ecn, now: self.now)
            }
            self.serverEvents += Self.events(&server)
            let fromServer = Self.drainWithECN(&server, now: self.now)
            self.server = consume server
            for var datagram in fromServer {
                guard network(false, &datagram) else { continue }
                let (path, ecn) = (datagram.path, datagram.ecn)
                var span = datagram.bytes.mutableSpan
                self.client.receive(&span, on: path, ecn: ecn, now: self.now)
            }
            self.clientEvents += Self.events(&self.client)
            if fromClient.isEmpty && fromServer.isEmpty { return }
        }
    }

    /// Moves the clock to the earliest deadline and fires the timers that are due.
    mutating func advanceToNextDeadline() {
        var deadline = self.client.nextDeadline
        if let serverDeadline = self.server?.nextDeadline, deadline == nil || serverDeadline < deadline! {
            deadline = serverDeadline
        }
        guard let deadline else { return }
        if deadline > self.now {
            self.now = deadline
        }
        self.client.handleTimeout(now: self.now)
        if var server = self.server.take() {
            server.handleTimeout(now: self.now)
            self.server = consume server
        }
    }
}

@available(Network 0.1.0, *)
final class QUICConnectionCoreTests: XCTestCase {
    func testHandshakeCompletes() {
        var pair = LockstepPair()
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertTrue(pair.server?.isHandshakeConfirmed ?? false)
    }

    func testRequestResponse() throws {
        var pair = LockstepPair()
        pair.exchange()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let request = [UInt8]("GET /".utf8)
        XCTAssertEqual(pair.client.write(request.span.bytes, to: streamID, fin: true), request.count)
        pair.exchange()
        XCTAssertTrue(pair.serverEvents.contains(.streamOpened(streamID)), "server events: \(pair.serverEvents)")

        guard var server = pair.server.take() else {
            XCTFail("No server")
            return
        }
        var received: [UInt8] = []
        var finished = false
        _ = server.read(from: streamID) { bytes, isFinished in
            received = [UInt8](copying: bytes)
            finished = isFinished
            return (bytes.byteCount, ())
        }
        XCTAssertEqual(received, request)
        XCTAssertTrue(finished)
        let response = [UInt8](repeating: 0x41, count: 5000)
        XCTAssertEqual(server.write(response.span.bytes, to: streamID, fin: true), response.count)
        pair.server = consume server
        pair.exchange()

        var responseReceived: [UInt8] = []
        var responseFinished = false
        while true {
            let progress: Int =
                pair.client.read(from: streamID) { bytes, isFinished in
                    responseReceived += [UInt8](copying: bytes)
                    responseFinished = isFinished
                    return (bytes.byteCount, bytes.byteCount)
                } ?? 0
            if progress == 0 { break }
        }
        XCTAssertEqual(responseReceived.count, response.count)
        XCTAssertTrue(responseFinished)
        // Both directions are done once the client's FIN is acknowledged and the response read.
        pair.exchange()
        pair.clientEvents += LockstepPair.events(&pair.client)
        XCTAssertTrue(pair.clientEvents.contains(.streamClosed(streamID)), "client events: \(pair.clientEvents)")
    }

    func testLossIsRecoveredByRetransmission() throws {
        var pair = LockstepPair()
        pair.exchange()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 20_000)
        XCTAssertEqual(pair.client.write(payload.span.bytes, to: streamID, fin: true), payload.count)
        // Lose every third datagram towards the server once.
        pair.exchange(drop: { toServer, index in toServer && index % 3 == 1 })
        for _ in 0..<20 {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        guard var server = pair.server.take() else {
            XCTFail("No server")
            return
        }
        var received = 0
        var finished = false
        while true {
            let progress: Int =
                server.read(from: streamID) { bytes, isFinished in
                    received += bytes.byteCount
                    finished = isFinished
                    return (bytes.byteCount, bytes.byteCount)
                } ?? 0
            if progress == 0 { break }
        }
        pair.server = consume server
        XCTAssertEqual(received, payload.count)
        XCTAssertTrue(finished)
    }

    func testWritesPastTheFlowControlLimitArriveAsTheReaderConsumes() throws {
        var pair = LockstepPair()
        pair.exchange()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x43, count: 700_000)
        XCTAssertLessThan(pair.client.writableBytes(on: streamID), payload.count)
        XCTAssertEqual(pair.client.write(payload.span.bytes, to: streamID, fin: true), payload.count)
        var received = 0
        var finished = false
        for _ in 0..<200 where !finished {
            pair.exchange()
            guard var server = pair.server.take() else {
                XCTFail("No server")
                return
            }
            while true {
                let progress: Int =
                    server.read(from: streamID) { bytes, isFinished in
                        received += bytes.byteCount
                        finished = isFinished
                        return (bytes.byteCount, bytes.byteCount)
                    } ?? 0
                if progress == 0 { break }
            }
            pair.server = consume server
        }
        XCTAssertEqual(received, payload.count)
        XCTAssertTrue(finished)
        XCTAssertTrue(pair.clientEvents.contains(.streamWritable(streamID)), "client events: \(pair.clientEvents)")
    }

    func testSequentialRequestsBeyondTheStreamLimit() throws {
        var serverConfiguration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        serverConfiguration.initialMaxStreamsBidirectional = 4
        var pair = LockstepPair(serverConfiguration: serverConfiguration)
        pair.exchange()
        for request in 0..<40 {
            let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true), "request \(request)")
            pair.client.write([UInt8]("GET".utf8).span.bytes, to: streamID, fin: true)
            pair.exchange()
            guard var server = pair.server.take() else {
                XCTFail("No server")
                return
            }
            _ = server.read(from: streamID) { bytes, _ in (bytes.byteCount, ()) }
            server.write([UInt8]("OK".utf8).span.bytes, to: streamID, fin: true)
            pair.server = consume server
            pair.exchange()
            var finished = false
            _ = pair.client.read(from: streamID) { bytes, isFinished in
                finished = isFinished
                return (bytes.byteCount, ())
            }
            XCTAssertTrue(finished, "request \(request)")
            pair.exchange()
        }
    }

    func testLostRequestAndResponseAreRetransmitted() throws {
        for loseRequest in [true, false] {
            var pair = LockstepPair()
            pair.exchange()
            let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
            pair.client.write([UInt8]("GET".utf8).span.bytes, to: streamID, fin: true)
            var dropped = false
            // Lose the first datagram in the chosen direction that carries the stream data.
            let dropOnce: (Bool, Int) -> Bool = { toServer, _ in
                guard toServer == loseRequest, !dropped else { return false }
                dropped = true
                return true
            }
            pair.exchange(drop: dropOnce)
            var finished = false
            for _ in 0..<30 where !finished {
                if var server = pair.server.take() {
                    _ = server.read(from: streamID) { bytes, _ in (bytes.byteCount, ()) }
                    if server.hasStream(streamID) {
                        server.write([UInt8]("OK".utf8).span.bytes, to: streamID, fin: true)
                    }
                    pair.server = consume server
                }
                pair.exchange(drop: dropOnce)
                _ = pair.client.read(from: streamID) { bytes, isFinished in
                    if isFinished { finished = true }
                    return (bytes.byteCount, ())
                }
                if !finished {
                    pair.advanceToNextDeadline()
                    pair.exchange(drop: dropOnce)
                }
            }
            XCTAssertTrue(dropped)
            XCTAssertTrue(finished, "lost \(loseRequest ? "request" : "response") was not recovered")
        }
    }

    func testCloseReachesPeer() {
        var pair = LockstepPair()
        pair.exchange()
        pair.client.close(errorCode: 7, isApplication: true, reason: "bye", now: pair.now)
        pair.exchange()
        XCTAssertTrue(
            pair.serverEvents.isEmpty
                || !pair.serverEvents.contains(where: { if case .closed = $0 { return true } else { return false } }),
            "The server only reports closed after draining"
        )
        for _ in 0..<5 {
            pair.advanceToNextDeadline()
        }
        pair.clientEvents += LockstepPair.events(&pair.client)
        if var server = pair.server.take() {
            pair.serverEvents += LockstepPair.events(&server)
            pair.server = consume server
        }
        XCTAssertTrue(pair.clientEvents.contains(.closed(.local(errorCode: 7, isApplication: true))))
        XCTAssertTrue(pair.serverEvents.contains(.closed(.peer(errorCode: 7, isApplication: true, reason: "bye"))))
    }

    func testIdleTimeout() {
        var pair = LockstepPair()
        pair.exchange()
        for _ in 0..<10 {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        pair.clientEvents += LockstepPair.events(&pair.client)
        XCTAssertTrue(pair.clientEvents.contains(.closed(.idleTimeout)), "client events: \(pair.clientEvents)")
    }

    private static func configuration(idleTimeout: NetworkDuration) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.maxIdleTimeout = idleTimeout
        return configuration
    }

    /// Runs the timers of an otherwise quiet connection for `duration`.
    private static func idle(_ pair: inout LockstepPair, for duration: NetworkDuration) {
        let end = pair.now.advanced(by: duration)
        for _ in 0..<100 {
            pair.advanceToNextDeadline()
            pair.exchange()
            if pair.now >= end || (pair.client.isClosed && pair.server?.isClosed != false) { break }
        }
    }

    /// RFC 9000 Section 10.1: a zero max_idle_timeout disables the idle timeout.
    func testNoIdleTimeoutWhenBothSidesDisableIt() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(idleTimeout: .zero),
            serverConfiguration: Self.configuration(idleTimeout: .zero)
        )
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        Self.idle(&pair, for: .seconds(3600))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
        XCTAssertNil(pair.client.nextDeadline, "an idle connection without idle timeout needs no timer")
    }

    #if DEBUG
    /// The peer's max_idle_timeout goes up to 2^62 - 1 ms, more than a duration holds: a smaller
    /// local one wins, and without a local one it is capped (RFC 9000 Section 10.1).
    func testAHugePeerIdleTimeoutIsCapped() {
        let capped = NetworkDuration.milliseconds(QUICConnectionCore.maximumPeerIdleTimeoutMilliseconds)
        for (local, expected) in [(NetworkDuration.seconds(30), NetworkDuration.seconds(30)), (.zero, capped)] {
            var serverConfiguration = Self.configuration(idleTimeout: .seconds(30))
            serverConfiguration.transportParametersForTesting = { parameters in
                parameters.remove(.maxIdleTimeout)
                parameters.append(.maxIdleTimeout(value: (1 << 62) - 1))
            }
            var pair = LockstepPair(
                clientConfiguration: Self.configuration(idleTimeout: local),
                serverConfiguration: serverConfiguration
            )
            pair.exchange()
            XCTAssertTrue(pair.client.isHandshakeConfirmed, "local \(local)")
            XCTAssertEqual(pair.client.idleTimeout, expected, "local \(local)")
            // Packets keep moving the deadline.
            pair.client.injectedFrames.append([0x01])  // PING
            pair.exchange()
            XCTAssertNil(pair.client.closeReason, "local \(local)")
            XCTAssertNil(pair.server?.closeReason, "local \(local)")
            XCTAssertEqual(pair.client.idleDeadline, pair.now.advanced(by: expected), "local \(local)")
        }
    }
    #endif

    /// The effective idle timeout is the smaller of the two, and a disabled one doesn't count.
    func testTheIdleTimeoutIsTheSmallerNonzeroOne() {
        for (client, server, expected) in [
            (NetworkDuration.zero, NetworkDuration.seconds(5), NetworkDuration.seconds(5)),
            (.seconds(5), .zero, .seconds(5)),
            (.seconds(5), .seconds(20), .seconds(5)),
            (.seconds(20), .seconds(5), .seconds(5)),
        ] {
            var pair = LockstepPair(
                clientConfiguration: Self.configuration(idleTimeout: client),
                serverConfiguration: Self.configuration(idleTimeout: server)
            )
            pair.exchange()
            let quietSince = pair.now
            Self.idle(&pair, for: .seconds(60))
            let context = "client \(client), server \(server)"
            XCTAssertEqual(pair.client.closeReason, .idleTimeout, context)
            XCTAssertEqual(pair.server?.closeReason, .idleTimeout, context)
            // Closed within a second of the expected timeout.
            let elapsed = quietSince.duration(to: pair.now)
            XCTAssertGreaterThanOrEqual(elapsed, expected, context)
            XCTAssertLessThan(elapsed, expected + .seconds(1), context)
        }
    }
}

#endif
