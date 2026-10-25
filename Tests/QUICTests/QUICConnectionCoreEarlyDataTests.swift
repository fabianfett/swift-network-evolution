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

/// 0-RTT (RFC 9000 Section 4.6.1, RFC 9001 Section 4.6) between two state machines that share an
/// external PSK.
@available(Network 0.1.0, *)
final class QUICConnectionCoreEarlyDataTests: XCTestCase {
    private static let identity: [UInt8] = [0x65, 0x70, 0x73, 0x6b]
    private static let epsk: [UInt8] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
    ]
    private static let logPrefixer = LogPrefixer("[QUICConnectionCoreEarlyDataTests]")
    private static let protocolViolation: UInt64 = 0x0a

    private static func tlsOptions(
        earlyData: Bool,
        remembered: [UInt8]? = nil
    ) -> SwiftTLSProtocol.Options {
        var options = SwiftTLSProtocol.Options()
        options.applicationProtocols = ["qsm-test"]
        options.serverName = "quic-test.local"
        options.enableEarlyData = earlyData
        options.resumedQUICTransportParameters = remembered
        options.setExternalPSK(identity: Self.identity, epsk: Self.epsk)
        return options
    }

    /// The transport parameters a client remembers of a server with the default configuration,
    /// with changes.
    private static func remembered(
        _ change: (inout TransportParameters) -> Void = { _ in }
    ) throws -> [UInt8] {
        let defaults = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        var parameters = TransportParameters()
        parameters.append(.initialMaxData(value: defaults.initialMaxData))
        parameters.append(.initialMaxStreamDataBidirectionalLocal(value: defaults.initialMaxStreamDataBidirectionalLocal))
        parameters.append(
            .initialMaxStreamDataBidirectionalRemote(value: defaults.initialMaxStreamDataBidirectionalRemote)
        )
        parameters.append(.initialMaxStreamDataUnidirectional(value: defaults.initialMaxStreamDataUnidirectional))
        parameters.append(.initialMaxStreamsBidirectional(value: defaults.initialMaxStreamsBidirectional))
        parameters.append(.initialMaxStreamsUnidirectional(value: defaults.initialMaxStreamsUnidirectional))
        change(&parameters)
        return try parameters.serialize(forEarlyData: true)
    }

    /// A client that attempts 0-RTT with `remembered`, and a server that accepts it or not.
    private static func pair(
        remembered: [UInt8],
        serverAcceptsEarlyData: Bool = true,
        resendRejectedEarlyData: Bool = false
    ) -> LockstepPair {
        var clientConfiguration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        clientConfiguration.resendRejectedEarlyData = resendRejectedEarlyData
        return LockstepPair(
            clientConfiguration: clientConfiguration,
            clientTLSOptions: Self.tlsOptions(earlyData: true, remembered: remembered),
            serverTLSOptions: Self.tlsOptions(earlyData: serverAcceptsEarlyData)
        )
    }

    private static func vle(_ bytes: [UInt8], at offset: Int) -> (value: UInt64, length: Int) {
        let length = 1 << (bytes[offset] >> 6)
        var value = UInt64(bytes[offset] & 0x3f)
        for index in 1..<length {
            value = value << 8 | UInt64(bytes[offset + index])
        }
        return (value, length)
    }

    /// The type bits of the long-header packets coalesced in a datagram (RFC 9000 Section 17.2):
    /// 0 Initial, 1 0-RTT, 2 Handshake.
    private static func longHeaderTypes(_ datagram: [UInt8]) -> [UInt8] {
        var types: [UInt8] = []
        var offset = 0
        while offset < datagram.count, datagram[offset] & 0x80 != 0 {
            let type = (datagram[offset] >> 4) & 0x03
            types.append(type)
            var cursor = offset + 5
            cursor += 1 + Int(datagram[cursor])
            cursor += 1 + Int(datagram[cursor])
            if type == 0 {
                let token = Self.vle(datagram, at: cursor)
                cursor += token.length + Int(token.value)
            }
            let length = Self.vle(datagram, at: cursor)
            offset = cursor + length.length + Int(length.value)
        }
        return types
    }

    private static func readAll(_ core: inout QUICConnectionCore, _ streamID: UInt64) -> (bytes: [UInt8], fin: Bool) {
        var bytes: [UInt8] = []
        var fin = false
        while true {
            let consumed: Int? = core.read(from: streamID) { span, isFinished in
                bytes += [UInt8](copying: span)
                if isFinished { fin = true }
                return (span.byteCount, span.byteCount)
            }
            guard let consumed, consumed > 0 else { break }
        }
        return (bytes, fin)
    }

    private static func resumptionParameters(_ events: [QUICConnectionCore.Event]) -> [[UInt8]] {
        events.compactMap { event in
            if case .transportParametersForResumption(let bytes) = event { return bytes }
            return nil
        }
    }

    // MARK: Accepted

    func testEarlyDataArrivesBeforeTheHandshakeCompletes() throws {
        var pair = Self.pair(remembered: try Self.remembered())
        XCTAssertTrue(pair.client.canSendEarlyData)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        XCTAssertEqual(pair.client.write(Array("hello".utf8).span.bytes, to: streamID, fin: true), 5)

        // The first flight: an Initial with the ClientHello, and a 0-RTT packet with the data.
        let firstFlight = LockstepPair.drain(&pair.client, now: pair.now)
        let types = firstFlight.flatMap { Self.longHeaderTypes($0) }
        XCTAssertEqual(types.first, 0x00)
        XCTAssertTrue(types.contains(0x01), "no 0-RTT packet in \(types)")
        XCTAssertFalse(types.contains(0x02), "Handshake packet before the server's answer")
        XCTAssertTrue(firstFlight.allSatisfy { $0[0] & 0x80 != 0 }, "a 1-RTT packet before the handshake")
        pair.toServer = firstFlight

        // The server reads the data before the client's Finished arrives.
        pair.exchange(rounds: 1)
        XCTAssertTrue(pair.serverEvents.contains(.streamOpened(streamID)))
        XCTAssertTrue(pair.serverEvents.contains(.streamReadable(streamID)))
        XCTAssertFalse(pair.serverEvents.contains(.connected))
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertTrue(server.isEarlyDataAccepted)
        let received = Self.readAll(&server, streamID)
        XCTAssertEqual(received.bytes, Array("hello".utf8))
        XCTAssertTrue(received.fin)
        pair.server = consume server

        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertTrue(pair.serverEvents.contains(.connected))
        XCTAssertTrue(pair.client.isEarlyDataAccepted)
        XCTAssertFalse(pair.client.canSendEarlyData)
        // A client with 1-RTT keys is done with the 0-RTT ones (RFC 9001 Section 4.9.3).
        XCTAssertFalse(pair.client.protector.sealKeyReady(for: .earlyData))
        XCTAssertFalse(pair.clientEvents.contains(.earlyDataRejected))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testOnlyAClientWithEarlyDataGetsTransportParametersForResumption() throws {
        var pair = Self.pair(remembered: try Self.remembered())
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        let reported = Self.resumptionParameters(pair.clientEvents)
        XCTAssertEqual(reported.count, 1)
        XCTAssertEqual(Self.resumptionParameters(pair.serverEvents).count, 0)
        let bytes = try XCTUnwrap(reported.first)
        let parameters = try TransportParameters.deserialize(bytes.span, logPrefixer: Self.logPrefixer)
        XCTAssertEqual(parameters.intValue(.initialMaxStreamsBidirectional), 100)

        // What it reported is enough for 0-RTT on the next connection.
        var resumed = Self.pair(remembered: try XCTUnwrap(reported.first))
        XCTAssertTrue(resumed.client.canSendEarlyData)
        resumed.exchange()
        XCTAssertTrue(resumed.client.isEarlyDataAccepted)
        XCTAssertNil(resumed.client.closeReason)

        var withoutEarlyData = LockstepPair()
        withoutEarlyData.exchange()
        XCTAssertTrue(withoutEarlyData.clientEvents.contains(.connected))
        XCTAssertFalse(withoutEarlyData.client.canSendEarlyData)
        XCTAssertEqual(Self.resumptionParameters(withoutEarlyData.clientEvents).count, 0)
    }

    /// RFC 9000 Section 7.4.1: a server that accepts 0-RTT must not lower the limits the client
    /// remembered.
    func testAServerThatLowersARememberedLimitIsAProtocolViolation() throws {
        var pair = Self.pair(
            remembered: try Self.remembered {
                $0.remove(.initialMaxStreamsBidirectional)
                $0.append(.initialMaxStreamsBidirectional(value: 200))
            }
        )
        pair.exchange()
        XCTAssertFalse(pair.clientEvents.contains(.connected))
        XCTAssertEqual(
            pair.client.closeReason,
            .transportError(errorCode: Self.protocolViolation, reason: "Server reduced initial_max_streams_bidi")
        )
    }

    func testARememberedLimitTheServerKeepsIsFine() throws {
        var pair = Self.pair(
            remembered: try Self.remembered {
                $0.remove(.initialMaxStreamsBidirectional)
                $0.append(.initialMaxStreamsBidirectional(value: 50))
            }
        )
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertTrue(pair.client.isEarlyDataAccepted)
        XCTAssertNil(pair.client.closeReason)
    }

    /// RFC 9000 Section 12.4: 0-RTT packets carry no ACK, CRYPTO, NEW_TOKEN, HANDSHAKE_DONE, or
    /// frames about paths and connection IDs.
    func testAForbiddenFrameIn0RTTIsAProtocolViolation() throws {
        let frames: [(String, [UInt8])] = [
            ("HANDSHAKE_DONE", [0x1e]),
            ("NEW_TOKEN", [0x07, 0x01, 0xaa]),
            ("ACK", [0x02, 0x00, 0x00, 0x00, 0x00]),
            ("RETIRE_CONNECTION_ID", [0x19, 0x00]),
        ]
        for (name, frame) in frames {
            var pair = Self.pair(remembered: try Self.remembered())
            XCTAssertTrue(pair.client.canSendEarlyData)
            pair.client.injectedFrames.append(frame)
            pair.exchange()
            XCTAssertEqual(
                pair.server?.closeReason,
                .transportError(errorCode: Self.protocolViolation, reason: "Frame not allowed in 0-RTT"),
                name
            )
        }
    }

    func testAnAllowedFrameIn0RTTIsFine() throws {
        var pair = Self.pair(remembered: try Self.remembered())
        // PING.
        pair.client.injectedFrames.append([0x01])
        pair.exchange()
        XCTAssertTrue(pair.serverEvents.contains(.connected))
        XCTAssertNil(pair.server?.closeReason)
        XCTAssertNil(pair.client.closeReason)
    }

    /// What a 0-RTT packet raised stays raised when the client's transport parameters are
    /// reported again with its Finished.
    func testALimitRaisedIn0RTTOutlivesTheHandshake() throws {
        var pair = Self.pair(remembered: try Self.remembered())
        pair.client.raiseLocalMaxStreams(to: 150, bidirectional: true)
        pair.exchange(rounds: 1)
        XCTAssertFalse(pair.serverEvents.contains(.connected))
        XCTAssertEqual(pair.server?.peerMaxStreams(bidirectional: true), 150)
        pair.exchange()
        XCTAssertTrue(pair.serverEvents.contains(.connected))
        XCTAssertEqual(pair.server?.peerMaxStreams(bidirectional: true), 150)
        XCTAssertNil(pair.server?.closeReason)
    }

    // MARK: Rejected

    func testRejectedEarlyDataIsGoneAndTheStreamStartsOver() throws {
        var pair = Self.pair(remembered: try Self.remembered(), serverAcceptsEarlyData: false)
        XCTAssertTrue(pair.client.canSendEarlyData)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write(Array("early".utf8).span.bytes, to: streamID)
        let firstFlight = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertTrue(firstFlight.flatMap { Self.longHeaderTypes($0) }.contains(0x01))
        pair.toServer = firstFlight
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertEqual(pair.clientEvents.filter { $0 == .earlyDataRejected }.count, 1)
        XCTAssertFalse(pair.client.isEarlyDataAccepted)
        XCTAssertFalse(pair.client.protector.sealKeyReady(for: .earlyData))
        XCTAssertFalse(pair.serverEvents.contains(.streamOpened(streamID)))
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertFalse(server.isEarlyDataAccepted)
        XCTAssertEqual(Self.readAll(&server, streamID).bytes, [])
        pair.server = consume server

        // The application writes again, and the server reads exactly that.
        pair.client.write(Array("again".utf8).span.bytes, to: streamID, fin: true)
        pair.exchange()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let received = Self.readAll(&server, streamID)
        XCTAssertEqual(received.bytes, Array("again".utf8))
        XCTAssertTrue(received.fin)
        pair.server = consume server
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testRejectedEarlyDataIsSentAgainWhenConfigured() throws {
        var pair = Self.pair(
            remembered: try Self.remembered(),
            serverAcceptsEarlyData: false,
            resendRejectedEarlyData: true
        )
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write(Array("early".utf8).span.bytes, to: streamID, fin: true)
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.connected))
        XCTAssertFalse(pair.client.isEarlyDataAccepted)
        guard var server = pair.server.take() else { return XCTFail("No server") }
        let received = Self.readAll(&server, streamID)
        XCTAssertEqual(received.bytes, Array("early".utf8))
        XCTAssertTrue(received.fin)
        pair.server = consume server
        // Nothing arrives twice.
        pair.exchange()
        guard var server = pair.server.take() else { return XCTFail("No server") }
        XCTAssertEqual(Self.readAll(&server, streamID).bytes, [])
        pair.server = consume server
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }
}

#endif
