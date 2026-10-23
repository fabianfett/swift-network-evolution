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
}

#endif
