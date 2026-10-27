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

/// The checks of the peer's transport parameters (RFC 9000 Sections 7.3 and 18.2).
@available(Network 0.1.0, *)
final class QUICConnectionCoreTransportParameterTests: XCTestCase {
    enum Side {
        case client
        case server
    }

    /// Lets `side` send changed transport parameters, and returns the peer's close reason.
    private static func peerCloseReason(
        whenThe side: Side,
        sends change: @escaping (inout TransportParameters) -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> QUICConnectionCore.CloseReason? {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.transportParametersForTesting = change
        var pair =
            side == .client
            ? LockstepPair(clientConfiguration: configuration) : LockstepPair(serverConfiguration: configuration)
        pair.exchange()
        // The endpoint that rejected the parameters never reports the connection as connected.
        let rejectingEvents = side == .client ? pair.serverEvents : pair.clientEvents
        let closeReason = side == .client ? pair.server?.closeReason : pair.client.closeReason
        if closeReason != nil {
            XCTAssertFalse(rejectingEvents.contains(.connected), "events: \(rejectingEvents)", file: file, line: line)
        }
        return closeReason
    }

    private static func assertPeerCloses(
        whenThe side: Side,
        sends change: @escaping (inout TransportParameters) -> Void,
        with errorCode: UInt64,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let reason = Self.peerCloseReason(whenThe: side, sends: change, file: file, line: line)
        guard case .transportError(let code, _) = reason else {
            return XCTFail("close reason: \(String(describing: reason))", file: file, line: line)
        }
        XCTAssertEqual(code, errorCode, "close reason: \(String(describing: reason))", file: file, line: line)
    }

    func testValidParametersConnect() {
        var pair = LockstepPair()
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertTrue(pair.serverEvents.contains(.connected))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testTheInitialSourceConnectionIDMustBePresent() {
        for side in [Side.client, .server] {
            Self.assertPeerCloses(
                whenThe: side,
                sends: { $0.remove(.initialSCID) },
                with: CoreTransportError.transportParameterError
            )
        }
    }

    func testTheInitialSourceConnectionIDMustMatchThePackets() {
        for side in [Side.client, .server] {
            Self.assertPeerCloses(
                whenThe: side,
                sends: { $0.append(.initialSCID(connectionID: QUICConnectionID(8))) },
                with: CoreTransportError.protocolViolation
            )
        }
    }

    func testTheServerMustSendTheClientsOriginalDestinationConnectionID() {
        Self.assertPeerCloses(
            whenThe: .server,
            sends: { $0.remove(.originalDCID) },
            with: CoreTransportError.transportParameterError
        )
        Self.assertPeerCloses(
            whenThe: .server,
            sends: { $0.append(.originalDCID(connectionID: QUICConnectionID(8))) },
            with: CoreTransportError.protocolViolation
        )
    }

    func testARetrySourceConnectionIDWithoutRetryIsAnError() {
        Self.assertPeerCloses(
            whenThe: .server,
            sends: { $0.append(.retrySCID(connectionID: QUICConnectionID(8))) },
            with: CoreTransportError.protocolViolation
        )
    }

    func testAClientMustNotSendServerOnlyParameters() {
        let serverOnly: [TransportParameter] = [
            .originalDCID(connectionID: QUICConnectionID(8)),
            .retrySCID(connectionID: QUICConnectionID(8)),
            .statelessResetToken(statelessResetToken: QUICStatelessResetToken()),
        ]
        for parameter in serverOnly {
            Self.assertPeerCloses(
                whenThe: .client,
                sends: { $0.append(parameter) },
                with: CoreTransportError.transportParameterError
            )
        }
    }

    func testOutOfRangeValuesAreAnError() {
        let invalid: [TransportParameter] = [
            .maxUDPPayloadSize(value: 1199),
            .ackDelayExponent(value: 21),
            .maxAckDelay(duration: .milliseconds(1 << 14)),
            .activeConnectionIDLimit(value: 1),
            .initialMaxStreamsBidirectional(value: (1 << 60) + 1),
            .initialMaxStreamsUnidirectional(value: (1 << 60) + 1),
        ]
        for parameter in invalid {
            for side in [Side.client, .server] {
                Self.assertPeerCloses(
                    whenThe: side,
                    sends: { $0.append(parameter) },
                    with: CoreTransportError.transportParameterError
                )
            }
        }
    }

    func testValuesAtTheLimitsAreAccepted() {
        let valid: [TransportParameter] = [
            .maxUDPPayloadSize(value: 1200),
            .ackDelayExponent(value: 20),
            .maxAckDelay(duration: .milliseconds((1 << 14) - 1)),
            .activeConnectionIDLimit(value: 2),
            .initialMaxStreamsBidirectional(value: 1 << 60),
            .initialMaxStreamsUnidirectional(value: 1 << 60),
        ]
        for parameter in valid {
            for side in [Side.client, .server] {
                XCTAssertNil(Self.peerCloseReason(whenThe: side, sends: { $0.append(parameter) }), "\(parameter)")
            }
        }
    }

    func testAHandshakeWithoutTransportParametersFailsWithMissingExtension() {
        // The client completes its handshake as if the server's had no transport parameters.
        var clientConfiguration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        clientConfiguration.ignoresPeerTransportParametersForTesting = true
        var pair = LockstepPair(clientConfiguration: clientConfiguration)
        pair.exchange()
        // CRYPTO_ERROR with the missing_extension alert (RFC 9001 Section 8.2).
        let code = CoreTransportError.cryptoError + 109
        XCTAssertFalse(pair.clientEvents.contains(.connected), "\(pair.clientEvents)")
        guard case .transportError(code, _) = pair.client.closeReason else {
            return XCTFail("client close reason: \(String(describing: pair.client.closeReason))")
        }
        guard case .peer(code, false, _) = pair.server?.closeReason else {
            return XCTFail("server close reason: \(String(describing: pair.server?.closeReason))")
        }
    }

    func testAClientDropsLongHeaderPacketsFromAnotherServerConnectionID() throws {
        var pair = LockstepPair()
        let now = pair.now
        let initial = LockstepPair.drain(&pair.client, now: now)
        let ids = LockstepPair.connectionIDs(ofInitial: try XCTUnwrap(initial.first))
        // Two servers answer the same Initial, each with a connection ID of its own.
        func makeServer() -> QUICConnectionCore {
            var server = QUICConnectionCore(
                serverWith: pair.serverConfiguration,
                localConnectionID: QUICConnectionID(8),
                originalDestinationConnectionID: ids.destination,
                peerConnectionID: ids.source,
                now: now
            )
            for var datagram in initial {
                var span = datagram.mutableSpan
                server.receive(&span, now: now)
            }
            return server
        }
        var server = makeServer()
        var impostor = makeServer()
        XCTAssertNotEqual(server.localConnectionID, impostor.localConnectionID)
        let flight = LockstepPair.drain(&server, now: now)
        _ = LockstepPair.drain(&impostor, now: now)
        // A later Initial from the other connection ID, which the client could open, closes the
        // connection if the client processes it.
        impostor.injectFrame([0x1c, 0x0a, 0x00, 0x00], in: .initial)
        let forged = LockstepPair.drain(&impostor, now: now)
        XCTAssertFalse(forged.isEmpty)
        for var datagram in flight + forged {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: now)
        }
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(pair.client.peerConnectionID, server.localConnectionID)
        pair.server = consume server
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }
}

#endif
