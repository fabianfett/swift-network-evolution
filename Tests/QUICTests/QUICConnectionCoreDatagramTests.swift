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

/// DATAGRAM frames (RFC 9221) in `QUICConnectionCore`.
@available(Network 0.1.0, *)
final class QUICConnectionCoreDatagramTests: XCTestCase {
    private static func configuration(maxDatagramFrameSize: UInt64?) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.maxDatagramFrameSize = maxDatagramFrameSize
        return configuration
    }

    private static func connectedPair(client: UInt64?, server: UInt64?) -> LockstepPair {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(maxDatagramFrameSize: client),
            serverConfiguration: Self.configuration(maxDatagramFrameSize: server)
        )
        pair.exchange()
        return pair
    }

    private static func readDatagrams(_ machine: inout QUICConnectionCore) -> [[UInt8]] {
        var datagrams: [[UInt8]] = []
        while let datagram = machine.readDatagram({ [UInt8](copying: $0) }) {
            datagrams.append(datagram)
        }
        return datagrams
    }

    func testDatagramsReachThePeerInOrder() throws {
        var pair = Self.connectedPair(client: 1200, server: 1200)
        let payloads: [[UInt8]] = [[1, 2, 3], [], Array(repeating: 0x44, count: 900)]
        for payload in payloads {
            XCTAssertTrue(pair.client.sendDatagram(payload.span.bytes))
        }
        pair.exchange()
        XCTAssertEqual(pair.serverEvents.filter { $0 == .datagramsReadable }.count, 1)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readDatagrams(&server), payloads)
        XCTAssertTrue(server.sendDatagram([UInt8]([9]).span.bytes))
        pair.server = consume server
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.datagramsReadable))
        XCTAssertEqual(Self.readDatagrams(&pair.client), [[9]])
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    /// Only the endpoint that advertised max_datagram_frame_size receives datagrams.
    func testAdvertisingIsOneDirectional() {
        var pair = Self.connectedPair(client: 1200, server: nil)
        XCTAssertEqual(pair.client.maxDatagramPayloadSize, 0)
        XCTAssertFalse(pair.client.sendDatagram([UInt8]([1]).span.bytes))
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertGreaterThan(server.maxDatagramPayloadSize, 0)
        XCTAssertTrue(server.sendDatagram([UInt8]([2]).span.bytes))
        pair.server = consume server
        pair.exchange()
        XCTAssertEqual(Self.readDatagrams(&pair.client), [[2]])
    }

    func testThePayloadSizeHonorsThePeersLimitAndThePacket() throws {
        var pair = Self.connectedPair(client: 100, server: 65535)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        // The client's limit includes the frame type and the two byte length.
        XCTAssertEqual(server.maxDatagramPayloadSize, 97)
        XCTAssertTrue(server.sendDatagram([UInt8](repeating: 1, count: 97).span.bytes))
        XCTAssertFalse(server.sendDatagram([UInt8](repeating: 1, count: 98).span.bytes))
        pair.server = consume server
        // The server's limit is larger than a packet, so the packet decides.
        let clientMaximum = pair.client.maxDatagramPayloadSize
        XCTAssertLessThan(clientMaximum, 1350)
        XCTAssertGreaterThan(clientMaximum, 1250)
        XCTAssertTrue(pair.client.sendDatagram([UInt8](repeating: 2, count: clientMaximum).span.bytes))
        XCTAssertFalse(pair.client.sendDatagram([UInt8](repeating: 2, count: clientMaximum + 1).span.bytes))
        pair.exchange()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readDatagrams(&server).map(\.count), [clientMaximum])
        pair.server = consume server
        XCTAssertEqual(Self.readDatagrams(&pair.client).map(\.count), [97])
    }

    func testADatagramWithoutOurLimitIsAProtocolViolation() {
        var pair = Self.connectedPair(client: nil, server: nil)
        // DATAGRAM with a length of one.
        pair.client.injectedFrames.append([0x31, 0x01, 0x05])
        pair.exchange()
        XCTAssertEqual(
            pair.server?.closeReason,
            .transportError(errorCode: CoreTransportError.protocolViolation, reason: "DATAGRAM frame too large")
        )
    }

    func testADatagramLargerThanOurLimitIsAProtocolViolation() {
        var pair = Self.connectedPair(client: nil, server: 10)
        // A 12 byte frame: type, length and ten bytes of payload.
        pair.client.injectedFrames.append([0x31, 0x0a] + [UInt8](repeating: 0, count: 10))
        pair.exchange()
        XCTAssertEqual(
            pair.server?.closeReason,
            .transportError(errorCode: CoreTransportError.protocolViolation, reason: "DATAGRAM frame too large")
        )
    }

    func testADatagramUpToOurLimitArrives() {
        var pair = Self.connectedPair(client: nil, server: 10)
        // A frame without a length extends to the end of the packet; ten bytes in total.
        pair.client.injectedFrames.append([0x30] + [UInt8](repeating: 7, count: 9))
        pair.exchange()
        XCTAssertNil(pair.server?.closeReason)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readDatagrams(&server), [[UInt8](repeating: 7, count: 9)])
        pair.server = consume server
    }

    func testLostDatagramsAreNotRetransmitted() {
        var pair = Self.connectedPair(client: 1200, server: 1200)
        XCTAssertTrue(pair.client.sendDatagram([UInt8]([1]).span.bytes))
        let lost = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(lost.count, 1)
        // The probe timeout resends what is lost, which doesn't include the datagram, until the
        // peer acknowledged the probe.
        XCTAssertTrue(pair.client.recovery.hasAckElicitingInFlight)
        for _ in 0..<5 where pair.client.recovery.hasAckElicitingInFlight {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertFalse(pair.client.recovery.hasAckElicitingInFlight)
        XCTAssertNil(pair.client.closeReason)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readDatagrams(&server), [])
        pair.server = consume server
    }

    func testDatagramsQueuedDuringTheHandshakeWaitForThePeersLimit() {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(maxDatagramFrameSize: 1200),
            serverConfiguration: Self.configuration(maxDatagramFrameSize: 1200)
        )
        XCTAssertTrue(pair.client.sendDatagram([UInt8]([1, 2]).span.bytes))
        XCTAssertTrue(pair.client.sendDatagram([UInt8](repeating: 0, count: 5000).span.bytes), "checked once known")
        pair.exchange()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readDatagrams(&server), [[1, 2]])
        pair.server = consume server
    }

    /// A pending acknowledgement doesn't keep a datagram as large as a packet from going out,
    /// and a datagram larger than the buffer the driver offers is dropped instead of blocking.
    func testAFullSizeDatagramIsNotCrowdedOutByAcknowledgements() {
        var pair = Self.connectedPair(client: 65535, server: 65535)
        let maximum = pair.client.maxDatagramPayloadSize
        for round in 0..<3 {
            // The server's packet makes the client owe an acknowledgement.
            guard var server = pair.server.take() else { return XCTFail("No server") }
            XCTAssertTrue(server.sendDatagram([UInt8]([UInt8(round)]).span.bytes))
            pair.server = consume server
            pair.exchange()
            XCTAssertTrue(pair.client.sendDatagram([UInt8](repeating: 3, count: maximum).span.bytes))
            let sent = LockstepPair.drain(&pair.client, now: pair.now)
            XCTAssertLessThanOrEqual(sent.count, 2, "round \(round)")
            pair.toServer = sent
            pair.exchange()
            guard var server2 = pair.server.take() else { return XCTFail("No server") }
            XCTAssertEqual(Self.readDatagrams(&server2).map(\.count), [maximum], "round \(round)")
            pair.server = consume server2
        }
        // A buffer smaller than the configured datagram size can't take the datagram.
        XCTAssertTrue(pair.client.sendDatagram([UInt8](repeating: 3, count: maximum).span.bytes))
        var buffer = [UInt8](repeating: 0, count: 600)
        var span = buffer.mutableSpan
        _ = pair.client.send(into: &span, now: pair.now)
        XCTAssertEqual(pair.client.datagramsToSend.count, 0)
    }

    func testTheClientPadsItsInitialToTheConfiguredSize() {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialDatagramSize = 1300
        var pair = LockstepPair(clientConfiguration: configuration)
        let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(datagrams.first?.count, 1300)
        // Never below 1200 bytes.
        configuration.initialDatagramSize = 1000
        var small = LockstepPair(clientConfiguration: configuration)
        XCTAssertEqual(LockstepPair.drain(&small.client, now: small.now).first?.count, 1200)
    }
}

#endif
