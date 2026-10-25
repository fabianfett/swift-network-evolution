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

#if IMPORT_CRYPTO && !NETWORK_NO_SWIFT_QUIC && DEBUG

/// Connection IDs (RFC 9000 Sections 5.1 and 19.15-19.16) in `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreConnectionIDTests: XCTestCase {
    private static func configuration(
        automatic: Bool = true,
        limit: UInt64 = 8,
        maxIssued: Int = 8
    ) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.automaticallyIssueConnectionIDs = automatic
        configuration.activeConnectionIDLimit = limit
        configuration.maxIssuedConnectionIDs = maxIssued
        return configuration
    }

    private static func connectedPair(
        client: QUICConnectionCore.Configuration = configuration(),
        server: QUICConnectionCore.Configuration = configuration()
    ) -> LockstepPair {
        var pair = LockstepPair(clientConfiguration: client, serverConfiguration: server)
        pair.exchange()
        return pair
    }

    private static func newConnectionIDFrame(
        sequenceNumber: UInt8,
        retirePriorTo: UInt8 = 0,
        connectionID: QUICConnectionID = QUICConnectionID(8),
        token: QUICStatelessResetToken = QUICStatelessResetToken()
    ) -> [UInt8] {
        [0x18, sequenceNumber, retirePriorTo, UInt8(connectionID.length)] + connectionID.connectionID + token.token
    }

    private static func newLocal(_ events: [QUICConnectionCore.Event]) -> [QUICConnectionID] {
        events.compactMap {
            if case .newLocalConnectionID(_, let connectionID, _) = $0 { return connectionID }
            return nil
        }
    }

    private static func newPeer(_ events: [QUICConnectionCore.Event]) -> [QUICConnectionID] {
        events.compactMap {
            if case .newPeerConnectionID(_, let connectionID, _) = $0 { return connectionID }
            return nil
        }
    }

    private static func retiredLocal(_ events: [QUICConnectionCore.Event]) -> [QUICConnectionID] {
        events.compactMap {
            if case .retiredLocalConnectionID(let connectionID) = $0 { return connectionID }
            return nil
        }
    }

    private static func retiredPeer(_ events: [QUICConnectionCore.Event]) -> [QUICConnectionID] {
        events.compactMap {
            if case .retiredPeerConnectionID(let connectionID, _) = $0 { return connectionID }
            return nil
        }
    }

    private static func closeCode(_ reason: QUICConnectionCore.CloseReason?) -> UInt64? {
        if case .transportError(let code, _) = reason { return code }
        return nil
    }

    // MARK: Issuing

    func testIssuedConnectionIDsReachThePeerUpToItsLimit() {
        var pair = Self.connectedPair(
            client: Self.configuration(limit: 4, maxIssued: 6),
            server: Self.configuration(limit: 8, maxIssued: 6)
        )
        // The server keeps four, the client's limit, including the one of the handshake.
        let serverIssued = Self.newLocal(pair.serverEvents)
        XCTAssertEqual(serverIssued.count, 3)
        XCTAssertEqual(Self.newPeer(pair.clientEvents), serverIssued)
        // The client keeps six, its own maximum, below the server's limit of eight.
        let clientIssued = Self.newLocal(pair.clientEvents)
        XCTAssertEqual(clientIssued.count, 5)
        XCTAssertEqual(Self.newPeer(pair.serverEvents), clientIssued)
        // The tokens arrive with their connection IDs.
        let tokens = pair.serverEvents.compactMap { event -> QUICStatelessResetToken? in
            if case .newLocalConnectionID(_, _, let token) = event { return token }
            return nil
        }
        let known = pair.client.connectionIDs.peerStatelessResetTokens
        XCTAssertTrue(tokens.allSatisfy { known.contains($0) }, "tokens: \(tokens), known: \(known)")
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.withServer { $0.closeReason } ?? nil)
    }

    func testNoConnectionIDsAreIssuedUnlessAskedTo() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false),
            server: Self.configuration(automatic: false)
        )
        XCTAssertEqual(Self.newLocal(pair.serverEvents), [])
        XCTAssertEqual(Self.newLocal(pair.clientEvents), [])
        // The driver issues them.
        let connectionID = QUICConnectionID(8)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(connectionID, statelessResetToken: QUICStatelessResetToken()))
        XCTAssertFalse(server.issueConnectionID(connectionID, statelessResetToken: QUICStatelessResetToken()), "in use")
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.newPeer(pair.clientEvents), [connectionID])
    }

    func testIssuingStopsAtThePeersLimit() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false, limit: 3),
            server: Self.configuration(automatic: false)
        )
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(QUICConnectionID(8), statelessResetToken: QUICStatelessResetToken()))
        XCTAssertTrue(server.issueConnectionID(QUICConnectionID(8), statelessResetToken: QUICStatelessResetToken()))
        XCTAssertFalse(server.issueConnectionID(QUICConnectionID(8), statelessResetToken: QUICStatelessResetToken()))
        pair.server = consume server
    }

    func testAZeroLengthConnectionIDIssuesNone() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(),
            serverConfiguration: Self.configuration(),
            clientConnectionIDLength: 0
        )
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertEqual(Self.newLocal(pair.clientEvents), [])
        XCTAssertFalse(
            pair.client.issueConnectionID(QUICConnectionID(8), statelessResetToken: QUICStatelessResetToken())
        )
    }

    // MARK: Retiring

    func testRetirePriorToRetiresOlderConnectionIDsAndSwitches() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false),
            server: Self.configuration(automatic: false)
        )
        let original = pair.client.peerConnectionID
        let replacement = QUICConnectionID(8)
        let token = QUICStatelessResetToken()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(replacement, statelessResetToken: token))
        // A repeat of that NEW_CONNECTION_ID that retires everything before it still counts.
        server.injectedFrames.append(
            Self.newConnectionIDFrame(sequenceNumber: 1, retirePriorTo: 1, connectionID: replacement, token: token)
        )
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.retiredPeer(pair.clientEvents), [original])
        XCTAssertEqual(pair.client.peerConnectionID, replacement)
        XCTAssertEqual(Self.newPeer(pair.clientEvents), [replacement])
        // The server hears about it with RETIRE_CONNECTION_ID.
        XCTAssertEqual(Self.retiredLocal(pair.serverEvents), [original])
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testAConnectionIDBelowAnEarlierRetirePriorToIsRetiredAtOnce() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false),
            server: Self.configuration(automatic: false)
        )
        guard var server = pair.server.take() else { return XCTFail("No server") }
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 3, retirePriorTo: 3))
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 2))
        pair.server = consume server
        pair.exchange()
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(pair.client.connectionIDs.peer.map(\.sequenceNumber), [3])
        XCTAssertEqual(Self.newPeer(pair.clientEvents).count, 1)
    }

    func testRetiringTheConnectionIDInUseNeedsAnother() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false),
            server: Self.configuration(automatic: false)
        )
        let original = pair.client.peerConnectionID
        XCTAssertFalse(pair.client.retirePeerConnectionID(original), "there is no other one")
        let replacement = QUICConnectionID(8)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(replacement, statelessResetToken: QUICStatelessResetToken()))
        pair.server = consume server
        pair.exchange()
        XCTAssertTrue(pair.client.retirePeerConnectionID(original))
        XCTAssertEqual(pair.client.peerConnectionID, replacement)
        pair.exchange()
        XCTAssertEqual(Self.retiredLocal(pair.serverEvents), [original])
        XCTAssertFalse(pair.client.retirePeerConnectionID(QUICConnectionID(8)), "unknown")
    }

    /// The server replaces a connection ID the client retired.
    func testARetiredConnectionIDIsReplaced() {
        var pair = Self.connectedPair(client: Self.configuration(limit: 2), server: Self.configuration())
        let issued = Self.newLocal(pair.serverEvents)
        XCTAssertEqual(issued.count, 1)
        XCTAssertTrue(pair.client.retirePeerConnectionID(issued[0]))
        pair.exchange()
        XCTAssertEqual(Self.retiredLocal(pair.serverEvents), [issued[0]])
        let reissued = Self.newLocal(pair.serverEvents)
        XCTAssertEqual(reissued.count, 2)
        XCTAssertEqual(Self.newPeer(pair.clientEvents), reissued)
    }

    // MARK: Violations

    func testMoreConnectionIDsThanAllowedIsALimitError() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false, limit: 2),
            server: Self.configuration(automatic: false)
        )
        guard var server = pair.server.take() else { return XCTFail("No server") }
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 1))
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 2))
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.closeCode(pair.client.closeReason), CoreTransportError.connectionIDLimitError)
    }

    func testRetirePriorToAboveTheSequenceNumberIsAFrameEncodingError() {
        var pair = Self.connectedPair()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 9, retirePriorTo: 10))
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.closeCode(pair.client.closeReason), CoreTransportError.frameEncodingError)
    }

    func testAReusedSequenceNumberOrConnectionIDIsAProtocolViolation() {
        for reuseSequenceNumber in [true, false] {
            var pair = Self.connectedPair(
                client: Self.configuration(automatic: false),
                server: Self.configuration(automatic: false)
            )
            let connectionID = QUICConnectionID(8)
            let token = QUICStatelessResetToken()
            guard var server = pair.server.take() else { return XCTFail("No server") }
            server.injectedFrames.append(
                Self.newConnectionIDFrame(sequenceNumber: 1, connectionID: connectionID, token: token)
            )
            // Repeating the frame is fine.
            server.injectedFrames.append(
                Self.newConnectionIDFrame(sequenceNumber: 1, connectionID: connectionID, token: token)
            )
            if reuseSequenceNumber {
                server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 1))
            } else {
                server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 2, connectionID: connectionID))
            }
            pair.server = consume server
            pair.exchange()
            XCTAssertEqual(Self.closeCode(pair.client.closeReason), CoreTransportError.protocolViolation)
        }
    }

    func testRetiringAConnectionIDNeverIssuedIsAProtocolViolation() {
        var pair = Self.connectedPair(client: Self.configuration(), server: Self.configuration(automatic: false))
        pair.client.injectedFrames.append([0x19, 0x05])
        pair.exchange()
        XCTAssertEqual(Self.closeCode(pair.server?.closeReason), CoreTransportError.protocolViolation)
    }

    func testRetiringTheConnectionIDOfItsPacketIsAProtocolViolation() {
        var pair = Self.connectedPair()
        // The client's packets go to the server's connection ID of sequence number zero.
        pair.client.injectedFrames.append([0x19, 0x00])
        pair.exchange()
        XCTAssertEqual(Self.closeCode(pair.server?.closeReason), CoreTransportError.protocolViolation)
    }

    func testNewConnectionIDWithAZeroLengthConnectionIDIsAProtocolViolation() {
        // The server uses a zero-length connection ID, so the client must not receive another.
        var pair = LockstepPair(clientConfiguration: Self.configuration(), serverConfiguration: Self.configuration())
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: pair.toServer[0])
        pair.server = QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(0),
            originalDestinationConnectionID: ids.destination,
            peerConnectionID: ids.source,
            now: pair.now
        )
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        guard var server = pair.server.take() else { return XCTFail("No server") }
        server.injectedFrames.append(Self.newConnectionIDFrame(sequenceNumber: 1))
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.closeCode(pair.client.closeReason), CoreTransportError.protocolViolation)
    }

    // MARK: Using connection IDs

    func testAShortHeaderPacketToAnUnknownConnectionIDIsDropped() throws {
        var pair = Self.connectedPair()
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8]("GET".utf8).span.bytes, to: streamID, fin: true)
        // Address the server with a connection ID it never issued.
        pair.client.peerConnectionID = QUICConnectionID(8)
        let processed = pair.server?.packetsProcessed
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        for var datagram in pair.toServer {
            var span = datagram.mutableSpan
            server.receive(&span, now: pair.now)
        }
        pair.toServer.removeAll()
        XCTAssertEqual(server.packetsProcessed, processed)
        XCTAssertFalse(server.hasStream(streamID))
        pair.server = consume server
    }

    /// When the peer starts using a new connection ID, this endpoint switches to a new one of
    /// the peer's too, and replaces the one it used.
    func testThePeerUsingANewConnectionIDMakesThisEndpointSwitchToo() {
        var pair = Self.connectedPair(client: Self.configuration(limit: 3), server: Self.configuration(limit: 3))
        let serverOriginal = pair.server?.peerConnectionID
        let serverIssued = Self.newLocal(pair.serverEvents)
        XCTAssertEqual(serverIssued.count, 2)
        guard let next = pair.client.connectionIDs.peer.first(where: { $0.sequenceNumber == 1 }) else {
            return XCTFail("The client knows no connection ID of sequence number one")
        }
        pair.client.switchPeerConnectionID(to: next)
        pair.client.injectedFrames.append([0x01])
        pair.exchange()
        XCTAssertNotNil(pair.server?.peerConnectionID)
        XCTAssertNotEqual(pair.server?.peerConnectionID, serverOriginal)
        XCTAssertEqual(pair.server?.connectionIDs.usedLocalSequenceNumbers, [0, 1])
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testLostConnectionIDFramesAreSentAgain() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(automatic: false),
            serverConfiguration: Self.configuration(automatic: false)
        )
        pair.exchange()
        let connectionID = QUICConnectionID(8)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(connectionID, statelessResetToken: QUICStatelessResetToken()))
        // The first datagram with NEW_CONNECTION_ID is lost.
        XCTAssertFalse(LockstepPair.drain(&server, now: pair.now).isEmpty)
        pair.server = consume server
        for _ in 0..<5 where !Self.newPeer(pair.clientEvents).contains(connectionID) {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertEqual(Self.newPeer(pair.clientEvents), [connectionID])
        // And a lost RETIRE_CONNECTION_ID.
        XCTAssertTrue(pair.client.retirePeerConnectionID(connectionID))
        XCTAssertFalse(LockstepPair.drain(&pair.client, now: pair.now).isEmpty)
        for _ in 0..<5 where !Self.retiredLocal(pair.serverEvents).contains(connectionID) {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertEqual(Self.retiredLocal(pair.serverEvents), [connectionID])
    }

    func testTheTokenOfAnIssuedConnectionIDDetectsAStatelessReset() {
        var pair = Self.connectedPair(
            client: Self.configuration(automatic: false),
            server: Self.configuration(automatic: false)
        )
        let token = QUICStatelessResetToken([UInt8](repeating: 0x33, count: 16))!
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.issueConnectionID(QUICConnectionID(8), statelessResetToken: token))
        pair.server = consume server
        pair.exchange()
        var reset: [UInt8] = [0x41] + [UInt8](repeating: 0x77, count: 20) + token.token
        var span = reset.mutableSpan
        pair.client.receive(&span, now: pair.now)
        XCTAssertEqual(pair.client.closeReason, .statelessReset)
    }
}

#endif
