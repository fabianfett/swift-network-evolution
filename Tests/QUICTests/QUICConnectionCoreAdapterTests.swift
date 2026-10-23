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

/// What `QUICConnection` needs from the core to run on it.
@available(Network 0.1.0, *)
final class QUICConnectionCoreAdapterTests: XCTestCase {
    private static func configuration() -> QUICConnectionCore.Configuration {
        QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
    }

    /// A peer's max_ack_delay is a duration, which `TransportParameters.intValue` can't read.
    func testThePeersMaxAckDelayIsUsed() {
        var clientConfiguration = Self.configuration()
        clientConfiguration.maxAckDelay = .milliseconds(100)
        var pair = LockstepPair(clientConfiguration: clientConfiguration)
        pair.exchange()
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
        XCTAssertEqual(pair.server?.recovery.maxAckDelay, .milliseconds(100))
        XCTAssertEqual(pair.client.recovery.maxAckDelay, .milliseconds(25))
        XCTAssertNil(pair.client.peerTransportParameters?[.maxAckDelay])
    }

    func testTheServerSendsItsStatelessResetTokenAndCanDisableMigration() throws {
        let token = QUICStatelessResetToken()
        var serverConfiguration = Self.configuration()
        serverConfiguration.statelessResetToken = token
        serverConfiguration.disableActiveMigration = true
        var pair = LockstepPair(serverConfiguration: serverConfiguration)
        pair.exchange()
        let parameters = try XCTUnwrap(pair.client.peerTransportParameters)
        XCTAssertEqual(parameters[.statelessResetToken]?.statelessResetToken, token)
        XCTAssertNotNil(parameters[.disableActiveMigration])
        XCTAssertNil(pair.server?.peerTransportParameters?[.disableActiveMigration])
    }

    /// RFC 9000 Section 10.2.3: an application close in an Initial or Handshake packet becomes a
    /// transport close with APPLICATION_ERROR and no reason.
    func testAnApplicationCloseDuringTheHandshakeIsSentAsApplicationError() {
        var pair = LockstepPair()
        // The server gets the client's Initial and answers; the client hasn't completed yet.
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: pair.toServer[0])
        var server = QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(8),
            originalDestinationConnectionID: ids.destination,
            peerConnectionID: ids.source,
            now: pair.now
        )
        for var datagram in pair.toServer {
            var span = datagram.mutableSpan
            server.receive(&span, now: pair.now)
        }
        pair.toServer.removeAll()
        // The server's first flight is lost, so the client has no Handshake keys.
        XCTAssertFalse(LockstepPair.drain(&server, now: pair.now).isEmpty)
        server.close(errorCode: 42, isApplication: true, reason: "secret", now: pair.now)
        for var datagram in LockstepPair.drain(&server, now: pair.now) {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        XCTAssertEqual(
            pair.client.closeReason,
            .peer(errorCode: CoreTransportError.applicationError, isApplication: false, reason: "")
        )
    }

    func testRaisingTheLocalStreamLimitLetsThePeerOpenMoreStreams() throws {
        var serverConfiguration = Self.configuration()
        serverConfiguration.initialMaxStreamsBidirectional = 2
        var pair = LockstepPair(serverConfiguration: serverConfiguration)
        pair.exchange()
        XCTAssertEqual(pair.client.peerMaxStreams(bidirectional: true), 2)
        XCTAssertNotNil(pair.client.openStream(bidirectional: true))
        XCTAssertNotNil(pair.client.openStream(bidirectional: true))
        XCTAssertNil(pair.client.openStream(bidirectional: true))

        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(server.localMaxStreams(bidirectional: true), 2)
        server.raiseLocalMaxStreams(to: 5, bidirectional: true)
        // A limit never shrinks.
        server.raiseLocalMaxStreams(to: 3, bidirectional: true)
        XCTAssertEqual(server.localMaxStreams(bidirectional: true), 5)
        XCTAssertEqual(server.localMaxStreams(bidirectional: false), 100)
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(pair.client.peerMaxStreams(bidirectional: true), 5)
        for _ in 0..<3 {
            XCTAssertNotNil(pair.client.openStream(bidirectional: true))
        }
        XCTAssertNil(pair.client.openStream(bidirectional: true))
    }

    func testAConnectionIsQuiescentOnceEverythingIsAcknowledged() throws {
        var pair = LockstepPair()
        pair.exchange()
        // The handshake leaves acknowledgements to send; a few more rounds settle them.
        for _ in 0..<5 {
            pair.advanceToNextDeadline()
            pair.exchange()
            if pair.client.isQuiescent && pair.server?.isQuiescent == true { break }
        }
        XCTAssertTrue(pair.client.isQuiescent)
        XCTAssertEqual(pair.server?.isQuiescent, true)

        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8]("GET".utf8).span.bytes, to: streamID, fin: true)
        XCTAssertFalse(pair.client.isQuiescent, "a write waits to be sent")
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertFalse(pair.client.isQuiescent, "the request waits to be acknowledged")
    }
}

#endif
