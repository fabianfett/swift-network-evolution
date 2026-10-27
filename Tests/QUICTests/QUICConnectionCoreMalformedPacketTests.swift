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

/// Malformed packets from anyone on the path, before any key is authenticated, are dropped
/// without harm to the connection.
@available(Network 0.1.0, *)
final class QUICConnectionCoreMalformedPacketTests: XCTestCase {
    /// The Length fields too short for the packet number and the header protection sample:
    /// 4 bytes of packet number and 16 of sample (RFC 9001 Section 5.4.2).
    private static let shortLengths = 0..<20

    /// An Initial packet to `destination` whose Length field is `length`, followed by `length`
    /// bytes, padded with zeros to `paddedTo` bytes.
    private static func initial(to destination: QUICConnectionID, length: Int, paddedTo: Int = 0) -> [UInt8] {
        precondition(length < 64, "a one byte variable-length integer")
        var packet: [UInt8] = [0xc0, 0x00, 0x00, 0x00, 0x01, UInt8(destination.length)]
        packet += destination.connectionID
        // No source connection ID, no token.
        packet += [0x00, 0x00, UInt8(length)]
        packet += [UInt8](repeating: 0x5c, count: length)
        if packet.count < paddedTo {
            packet += [UInt8](repeating: 0, count: paddedTo - packet.count)
        }
        return packet
    }

    /// The server `pair` would make for the client's first `initial`.
    private static func server(for pair: borrowing LockstepPair, initial: [UInt8]) -> QUICConnectionCore {
        let ids = LockstepPair.connectionIDs(ofInitial: initial)
        return QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(8),
            originalDestinationConnectionID: ids.destination,
            peerConnectionID: ids.source,
            now: pair.now
        )
    }

    func testAServerDropsInitialsWithALengthTooShortForTheSample() {
        var pair = LockstepPair()
        let initials = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: initials[0])
        var server = Self.server(for: pair, initial: initials[0])
        for length in Self.shortLengths {
            var datagram = Self.initial(to: ids.destination, length: length, paddedTo: 1200)
            var span = datagram.mutableSpan
            server.receive(&span, now: pair.now)
            XCTAssertNil(server.closeReason, "Length \(length)")
        }
        pair.server = consume server
        pair.toServer = initials
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
    }

    /// The Length of a dropped packet still says where the next one starts (RFC 9000
    /// Section 12.2).
    func testAServerProcessesThePacketsCoalescedAfterOneWithAShortLength() {
        var pair = LockstepPair()
        var initials = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: initials[0])
        pair.server = Self.server(for: pair, initial: initials[0])
        initials[0] = Self.initial(to: ids.destination, length: 3) + initials[0]
        pair.toServer = initials
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
    }

    func testAClientDropsInitialsWithALengthTooShortForTheSample() {
        var pair = LockstepPair()
        let initials = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: initials[0])
        for length in Self.shortLengths {
            var datagram = Self.initial(to: ids.source, length: length, paddedTo: 1200)
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
            XCTAssertNil(pair.client.closeReason, "Length \(length)")
        }
        pair.toServer = initials
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected), "client events: \(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.connected), "server events: \(pair.serverEvents)")
        // The connection still carries data.
        pair.client.injectedFrames.append([0x01])
        pair.exchange()
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }
}

#endif
