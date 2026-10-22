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
private struct LockstepPair: ~Copyable {
    var client: QUICConnectionCore
    var server: QUICConnectionCore?
    var now = NetworkClock.Instant(milliseconds: 1_000)
    let serverConfiguration: QUICConnectionCore.Configuration
    /// Datagrams in flight, per direction.
    var toServer: [[UInt8]] = []
    var toClient: [[UInt8]] = []
    var clientEvents: [QUICConnectionCore.Event] = []
    var serverEvents: [QUICConnectionCore.Event] = []

    init(
        clientConfiguration: QUICConnectionCore.Configuration? = nil,
        serverConfiguration: QUICConnectionCore.Configuration? = nil
    ) {
        let serverKey = P256.Signing.PrivateKey()
        var clientTLS = SwiftTLSProtocol.Options()
        clientTLS.applicationProtocols = ["qsm-test"]
        clientTLS.serverName = "quic-test.local"
        clientTLS.trustedRawPublicKeyCertificates = [[UInt8](serverKey.publicKey.derRepresentation)]
        var serverTLS = SwiftTLSProtocol.Options()
        serverTLS.applicationProtocols = ["qsm-test"]
        serverTLS.rawPrivateKey = [UInt8](serverKey.rawRepresentation)

        var clientConfiguration = clientConfiguration ?? QUICConnectionCore.Configuration(tlsOptions: clientTLS)
        clientConfiguration.tlsOptions = clientTLS
        var serverConfiguration = serverConfiguration ?? QUICConnectionCore.Configuration(tlsOptions: serverTLS)
        serverConfiguration.tlsOptions = serverTLS
        self.serverConfiguration = serverConfiguration
        self.client = QUICConnectionCore(
            clientWith: clientConfiguration,
            localConnectionID: QUICConnectionID(8),
            destinationConnectionID: QUICConnectionID(8),
            now: self.now
        )
    }

    static func drain(_ machine: inout QUICConnectionCore, now: NetworkClock.Instant) -> [[UInt8]] {
        var datagrams: [[UInt8]] = []
        var buffer = [UInt8](repeating: 0, count: 1500)
        while true {
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
                var span = datagram.mutableSpan
                server.receive(&span, now: self.now)
            }
            self.toServer.removeAll()
            self.serverEvents += Self.events(&server)
            self.toClient += Self.drain(&server, now: self.now)
            for var datagram in self.toClient {
                defer { index += 1 }
                if drop(false, index) { continue }
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
}

#endif
