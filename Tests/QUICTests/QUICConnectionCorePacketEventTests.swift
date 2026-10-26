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

/// The packet events `QUICConnectionCore` records for qlog.
@available(Network 0.1.0, *)
final class QUICConnectionCorePacketEventTests: XCTestCase {
    private typealias PacketEvent = QUICConnectionCore.PacketEvent

    private static func configuration(recording: Bool) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.recordsPacketEvents = recording
        return configuration
    }

    private static func packetEvents(_ machine: inout QUICConnectionCore) -> [PacketEvent] {
        var events: [PacketEvent] = []
        while let event = machine.nextPacketEvent() {
            events.append(event)
        }
        return events
    }

    func testTheHandshakeIsRecordedPacketByPacket() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(recording: true),
            serverConfiguration: Self.configuration(recording: true)
        )
        let firstDatagram = LockstepPair.drain(&pair.client, now: pair.now)
        let firstSent = Self.packetEvents(&pair.client)
        // The client's first Initial: CRYPTO with the ClientHello, padded to 1200 bytes.
        XCTAssertEqual(firstSent.count, 1)
        let initial = try XCTUnwrap(firstSent.first)
        XCTAssertEqual(initial.kind, .sent)
        XCTAssertEqual(initial.packetType, .initial)
        XCTAssertEqual(initial.packetNumber, 0)
        XCTAssertEqual(initial.size, firstDatagram.first?.count)
        XCTAssertEqual(initial.frames, [.crypto, .padding])
        XCTAssertEqual(initial.time, pair.now)
        pair.toServer += firstDatagram
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)

        let client = Self.packetEvents(&pair.client)
        guard var server = pair.server.take() else {
            XCTFail("No server")
            return
        }
        let serverEvents = Self.packetEvents(&server)
        pair.server = consume server

        // The server received the client's Initial first.
        let firstReceived = try XCTUnwrap(serverEvents.first { $0.kind == .received })
        XCTAssertEqual(firstReceived.packetType, .initial)
        XCTAssertEqual(firstReceived.packetNumber, 0)
        XCTAssertEqual(firstReceived.frames.first, .crypto)
        XCTAssertTrue(firstReceived.frames.contains(.padding))

        for type in [PacketEvent.PacketType.initial, .handshake, .oneRTT] {
            XCTAssertTrue(client.contains { $0.kind == .received && $0.packetType == type }, "client received \(type)")
            XCTAssertTrue(serverEvents.contains { $0.kind == .sent && $0.packetType == type }, "server sent \(type)")
        }
        XCTAssertTrue(
            serverEvents.contains { $0.kind == .sent && $0.frames.contains(.handshakeDone) },
            "the server sends HANDSHAKE_DONE"
        )
        XCTAssertTrue(client.contains { $0.kind == .received && $0.frames.contains(.handshakeDone) })
        // What one side sent, the other received, packet for packet: nothing was lost.
        let sentByServer = serverEvents.filter { $0.kind == .sent }.map { "\($0.packetType) \($0.packetNumber)" }
        let receivedByClient = client.filter { $0.kind == .received }.map { "\($0.packetType) \($0.packetNumber)" }
        XCTAssertEqual(Set(sentByServer), Set(receivedByClient))
        XCTAssertFalse(client.contains { $0.kind == .lost })
    }

    func testALostPacketIsRecorded() throws {
        var pair = LockstepPair(clientConfiguration: Self.configuration(recording: true))
        pair.exchange()
        _ = Self.packetEvents(&pair.client)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 10_000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        // The first datagram with stream data never arrives; the later ones are acknowledged.
        pair.exchange(drop: { toServer, index in toServer && index == 0 })
        for _ in 0..<10 {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        let events = Self.packetEvents(&pair.client)
        let lost = try XCTUnwrap(events.first { $0.kind == .lost })
        XCTAssertEqual(lost.packetType, .oneRTT)
        XCTAssertTrue(lost.frames.isEmpty)
        let sent = try XCTUnwrap(
            events.first { $0.kind == .sent && $0.packetType == .oneRTT && $0.packetNumber == lost.packetNumber }
        )
        XCTAssertTrue(sent.frames.contains(.stream))
        XCTAssertEqual(lost.size, sent.size)
    }

    func testTheConnectionCloseIsRecorded() {
        var pair = LockstepPair(clientConfiguration: Self.configuration(recording: true))
        pair.exchange()
        _ = Self.packetEvents(&pair.client)
        pair.client.close(errorCode: 0, isApplication: true, now: pair.now)
        _ = LockstepPair.drain(&pair.client, now: pair.now)
        let events = Self.packetEvents(&pair.client)
        XCTAssertEqual(events.map(\.kind), [.sent])
        XCTAssertEqual(events.first?.frames, [.connectionClose])
        XCTAssertEqual(events.first?.packetType, .oneRTT)
    }

    func testNothingIsRecordedUnlessConfigured() {
        var pair = LockstepPair()
        pair.exchange()
        XCTAssertNil(pair.client.nextPacketEvent())
        XCTAssertTrue(pair.client.packetEvents.isEmpty)
        XCTAssertTrue(pair.client.receivedFrameTypes.isEmpty)
    }
}

#endif
