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

// MARK: - Frames a peer can send

/// Encodes QUIC frames (RFC 9000 § 19) byte by byte, independently of the codec under test.
private enum Frame {
    static func vle(_ value: UInt64) -> [UInt8] {
        switch value {
        case 0..<(1 << 6):
            return [UInt8(value)]
        case 0..<(1 << 14):
            return [UInt8(0x40 | (value >> 8)), UInt8(value & 0xff)]
        case 0..<(1 << 30):
            return (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * (3 - $0))) | ($0 == 0 ? 0x80 : 0) }
        default:
            return (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * (7 - $0))) | ($0 == 0 ? 0xc0 : 0) }
        }
    }

    static func stream(_ id: UInt64, offset: UInt64 = 0, _ data: [UInt8], fin: Bool = false) -> [UInt8] {
        let type: UInt64 = 0x08 | 0x04 | 0x02 | (fin ? 0x01 : 0)
        return vle(type) + vle(id) + vle(offset) + vle(UInt64(data.count)) + data
    }

    static func crypto(offset: UInt64, _ data: [UInt8]) -> [UInt8] {
        vle(0x06) + vle(offset) + vle(UInt64(data.count)) + data
    }

    static func resetStream(_ id: UInt64, errorCode: UInt64, finalSize: UInt64) -> [UInt8] {
        vle(0x04) + vle(id) + vle(errorCode) + vle(finalSize)
    }

    static func stopSending(_ id: UInt64, errorCode: UInt64) -> [UInt8] {
        vle(0x05) + vle(id) + vle(errorCode)
    }

    static func maxData(_ maximum: UInt64) -> [UInt8] {
        vle(0x10) + vle(maximum)
    }

    static func maxStreamData(_ id: UInt64, _ maximum: UInt64) -> [UInt8] {
        vle(0x11) + vle(id) + vle(maximum)
    }

    static func maxStreams(bidirectional: Bool, _ maximum: UInt64) -> [UInt8] {
        vle(bidirectional ? 0x12 : 0x13) + vle(maximum)
    }

    static func ack(largest: UInt64) -> [UInt8] {
        self.ack(largest: largest, delay: 0)
    }

    static func ack(largest: UInt64, delay: UInt64) -> [UInt8] {
        vle(0x02) + vle(largest) + vle(delay) + vle(0) + vle(0)
    }

    static let handshakeDone: [UInt8] = [0x1e]
}

/// RFC 9000 § 20.1.
private enum TransportErrorCode {
    static let flowControl: UInt64 = 0x3
    static let streamLimit: UInt64 = 0x4
    static let streamState: UInt64 = 0x5
    static let finalSize: UInt64 = 0x6
    static let frameEncoding: UInt64 = 0x7
    static let protocolViolation: UInt64 = 0xa
}

// Stream IDs (RFC 9000 § 2.1): the two low bits are the initiator and the directionality.
private let clientBidirectional: UInt64 = 0
private let serverBidirectional: UInt64 = 1
private let clientUnidirectional: UInt64 = 2
private let serverUnidirectional: UInt64 = 3

@available(Network 0.1.0, *)
extension LockstepPair {
    mutating func withServer<Result>(_ body: (inout QUICConnectionCore) -> Result) -> Result? {
        guard var server = self.server.take() else { return nil }
        let result = body(&server)
        self.server = consume server
        return result
    }

    /// Sends raw frames from the server to the client, then lets the two settle.
    mutating func sendFromServer(_ frames: [UInt8]...) {
        self.withServer { $0.injectedFrames += frames }
        self.exchange()
    }

    /// Sends raw frames from the client to the server, then lets the two settle.
    mutating func sendFromClient(_ frames: [UInt8]...) {
        self.client.injectedFrames += frames
        self.exchange()
    }
}

@available(Network 0.1.0, *)
private func transportErrorCode(_ reason: QUICConnectionCore.CloseReason?) -> UInt64? {
    guard case .transportError(let code, _) = reason else { return nil }
    return code
}

@available(Network 0.1.0, *)
private func peerErrorCode(_ reason: QUICConnectionCore.CloseReason?) -> UInt64? {
    guard case .peer(let code, false, _) = reason else { return nil }
    return code
}

// MARK: - Misbehaving peers

/// Each test makes one side break a rule of RFC 9000 and checks that the other side closes the
/// connection with the transport error the RFC mandates, and that the error reaches the peer.
@available(Network 0.1.0, *)
final class QUICConnectionCoreProtocolViolationTests: XCTestCase {
    private func assertClientCloses(
        with code: UInt64,
        _ pair: inout LockstepPair,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let clientReason = pair.client.closeReason
        let serverReason = pair.server?.closeReason
        XCTAssertEqual(
            transportErrorCode(clientReason),
            code,
            "client close reason: \(String(describing: clientReason))",
            file: file,
            line: line
        )
        XCTAssertEqual(
            peerErrorCode(serverReason),
            code,
            "server close reason: \(String(describing: serverReason))",
            file: file,
            line: line
        )
    }

    private func assertServerCloses(
        with code: UInt64,
        _ pair: inout LockstepPair,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let clientReason = pair.client.closeReason
        let serverReason = pair.server?.closeReason
        XCTAssertEqual(
            transportErrorCode(serverReason),
            code,
            "server close reason: \(String(describing: serverReason))",
            file: file,
            line: line
        )
        XCTAssertEqual(
            peerErrorCode(clientReason),
            code,
            "client close reason: \(String(describing: clientReason))",
            file: file,
            line: line
        )
    }

    private func connectedPair(
        clientConfiguration: QUICConnectionCore.Configuration? = nil
    ) -> LockstepPair {
        var pair = LockstepPair(clientConfiguration: clientConfiguration)
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertNil(pair.client.closeReason)
        return pair
    }

    func testStreamFrameForAnUnopenedLocalStreamIsAStreamStateError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(clientBidirectional, [1, 2, 3]))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testStreamFrameOnASendOnlyStreamIsAStreamStateError() throws {
        var pair = self.connectedPair()
        let id = try XCTUnwrap(pair.client.openStream(bidirectional: false))
        XCTAssertEqual(id, clientUnidirectional)
        pair.client.write([UInt8]("x".utf8).span.bytes, to: id)
        pair.exchange()
        pair.sendFromServer(Frame.stream(id, [1]))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testResetStreamOnASendOnlyStreamIsAStreamStateError() throws {
        var pair = self.connectedPair()
        let id = try XCTUnwrap(pair.client.openStream(bidirectional: false))
        pair.client.write([UInt8]("x".utf8).span.bytes, to: id)
        pair.exchange()
        pair.sendFromServer(Frame.resetStream(id, errorCode: 1, finalSize: 0))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testStopSendingOnAReceiveOnlyStreamIsAStreamStateError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverUnidirectional, [1]))
        XCTAssertNil(pair.client.closeReason)
        pair.sendFromServer(Frame.stopSending(serverUnidirectional, errorCode: 1))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testStopSendingForAnUnopenedLocalStreamIsAStreamStateError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stopSending(clientBidirectional, errorCode: 1))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testMaxStreamDataOnAReceiveOnlyStreamIsAStreamStateError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverUnidirectional, [1]))
        pair.sendFromServer(Frame.maxStreamData(serverUnidirectional, 1 << 20))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testMaxStreamDataForAnUnopenedLocalStreamIsAStreamStateError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.maxStreamData(clientBidirectional, 1 << 20))
        self.assertClientCloses(with: TransportErrorCode.streamState, &pair)
    }

    func testDataPastTheStreamLimitIsAFlowControlError() {
        var pair = self.connectedPair()
        let window = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
            .initialMaxStreamDataBidirectionalRemote
        pair.sendFromServer(Frame.stream(serverBidirectional, offset: window, [1]))
        self.assertClientCloses(with: TransportErrorCode.flowControl, &pair)
    }

    func testDataUpToTheStreamLimitIsAccepted() {
        var pair = self.connectedPair()
        let window = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
            .initialMaxStreamDataBidirectionalRemote
        pair.sendFromServer(Frame.stream(serverBidirectional, offset: window - 1, [1]))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertTrue(pair.client.hasStream(serverBidirectional))
    }

    func testDataPastTheConnectionLimitIsAFlowControlError() {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 1000
        var pair = self.connectedPair(clientConfiguration: configuration)
        // Each stream is within its own limit; together they exceed the connection's.
        pair.sendFromServer(
            Frame.stream(serverBidirectional, [UInt8](repeating: 1, count: 600)),
            Frame.stream(serverBidirectional + 4, [UInt8](repeating: 2, count: 401))
        )
        self.assertClientCloses(with: TransportErrorCode.flowControl, &pair)
    }

    func testRetransmittedDataDoesNotCountTwiceAgainstTheConnectionLimit() {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 1000
        var pair = self.connectedPair(clientConfiguration: configuration)
        let data = [UInt8](repeating: 1, count: 600)
        pair.sendFromServer(Frame.stream(serverBidirectional, data))
        pair.sendFromServer(Frame.stream(serverBidirectional, data))
        pair.sendFromServer(Frame.stream(serverBidirectional, offset: 300, data))
        XCTAssertNil(pair.client.closeReason)
    }

    func testOpeningStreamsPastTheLimitIsAStreamLimitError() {
        var pair = self.connectedPair()
        let limit = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
            .initialMaxStreamsBidirectional
        // The limit-th server stream is the last one allowed.
        pair.sendFromServer(Frame.stream(serverBidirectional + 4 * (limit - 1), [1]))
        XCTAssertNil(pair.client.closeReason)
        pair.sendFromServer(Frame.stream(serverBidirectional + 4 * limit, [1]))
        self.assertClientCloses(with: TransportErrorCode.streamLimit, &pair)
    }

    func testDataPastTheFinalSizeIsAFinalSizeError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2, 3], fin: true))
        XCTAssertNil(pair.client.closeReason)
        pair.sendFromServer(Frame.stream(serverBidirectional, offset: 3, [4]))
        self.assertClientCloses(with: TransportErrorCode.finalSize, &pair)
    }

    func testAChangedFinalSizeIsAFinalSizeError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2, 3], fin: true))
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2], fin: true))
        self.assertClientCloses(with: TransportErrorCode.finalSize, &pair)
    }

    func testResetStreamBelowTheReceivedDataIsAFinalSizeError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2, 3]))
        pair.sendFromServer(Frame.resetStream(serverBidirectional, errorCode: 1, finalSize: 2))
        self.assertClientCloses(with: TransportErrorCode.finalSize, &pair)
    }

    func testResetStreamFinalSizePastTheConnectionLimitIsAFlowControlError() {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 1000
        var pair = self.connectedPair(clientConfiguration: configuration)
        // RFC 9000 § 4.5: the final size of a reset stream counts towards connection flow control.
        pair.sendFromServer(
            Frame.stream(serverBidirectional, [UInt8](repeating: 1, count: 500)),
            Frame.resetStream(serverBidirectional + 4, errorCode: 1, finalSize: 501)
        )
        self.assertClientCloses(with: TransportErrorCode.flowControl, &pair)
    }

    func testResetStreamFinalSizePastTheStreamLimitIsAFlowControlError() {
        var pair = self.connectedPair()
        let window = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
            .initialMaxStreamDataBidirectionalRemote
        pair.sendFromServer(Frame.resetStream(serverBidirectional, errorCode: 1, finalSize: window + 1))
        self.assertClientCloses(with: TransportErrorCode.flowControl, &pair)
    }

    func testResetStreamReturnsItsFinalSizeToTheConnectionWindow() throws {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 1000
        var pair = self.connectedPair(clientConfiguration: configuration)
        // The server sends 900 bytes the client never reads, then resets the stream.
        let first: UInt64? =
            pair.withServer { server in
                guard let id = server.openStream(bidirectional: true) else { return nil }
                server.write([UInt8](repeating: 1, count: 900).span.bytes, to: id)
                return id
            } ?? nil
        let firstID = try XCTUnwrap(first)
        pair.exchange()
        pair.withServer { $0.resetStream(firstID, errorCode: 1) }
        pair.exchange()
        XCTAssertTrue(pair.clientEvents.contains(.streamReset(firstID, errorCode: 1)), "\(pair.clientEvents)")
        // The reset bytes are as good as read, so the server may send more than the initial limit.
        let response = [UInt8](repeating: 2, count: 2000)
        let second: UInt64? =
            pair.withServer { server in
                guard let id = server.openStream(bidirectional: true) else { return nil }
                server.write(response.span.bytes, to: id, fin: true)
                return id
            } ?? nil
        let streamID = try XCTUnwrap(second)
        var received: [UInt8] = []
        var finished = false
        for _ in 0..<10 where !finished {
            pair.exchange()
            while true {
                let consumed: Int? = pair.client.read(from: streamID) { bytes, isFinished in
                    received += [UInt8](copying: bytes)
                    if isFinished { finished = true }
                    return (bytes.byteCount, bytes.byteCount)
                }
                guard let consumed, consumed > 0 else { break }
            }
        }
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(received.count, response.count)
        XCTAssertTrue(finished)
    }

    func testResetStreamDisagreeingWithTheFinIsAFinalSizeError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2, 3], fin: true))
        pair.sendFromServer(Frame.resetStream(serverBidirectional, errorCode: 1, finalSize: 5))
        self.assertClientCloses(with: TransportErrorCode.finalSize, &pair)
    }

    func testADuplicatedPacketIsProcessedOnce() {
        var pair = self.connectedPair()
        pair.client.injectedFrames.append([0x1a] + [UInt8](repeating: 4, count: 8))  // PATH_CHALLENGE
        let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
        let now = pair.now
        let pending: [UInt64] =
            pair.withServer { server in
                for datagram in datagrams + datagrams {
                    var copy = datagram
                    var span = copy.mutableSpan
                    server.receive(&span, now: now)
                }
                return server.paths[.initial]?.pendingResponses ?? []
            } ?? []
        // A processed duplicate would be answered twice.
        XCTAssertEqual(pending.count, 1)
    }

    func testAnEmptyResponseIsReadEvenAfterTheRequestWasAcknowledged() throws {
        var pair = self.connectedPair()
        let id = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8]("GET".utf8).span.bytes, to: id, fin: true)
        let request = LockstepPair.drain(&pair.client, now: pair.now)
        let now = pair.now
        let fin: [[UInt8]] =
            pair.withServer { server in
                for var datagram in request {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: now)
                }
                // The server's ACK of the request is lost...
                _ = LockstepPair.drain(&server, now: now)
                // ...and the empty response, sent next, carries no ACK.
                _ = server.read(from: id) { bytes, _ in (bytes.byteCount, ()) }
                server.write(RawSpan(), to: id, fin: true)
                return LockstepPair.drain(&server, now: now)
            } ?? []
        for var datagram in fin {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        // The ACK of the request arrives later, before the client reads.
        for _ in 0..<5 {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertTrue(pair.clientEvents.contains(.streamReadable(id)), "\(pair.clientEvents)")
        var finished = false
        let read: Void? = pair.client.read(from: id) { bytes, isFinished in
            finished = isFinished
            return (bytes.byteCount, ())
        }
        XCTAssertNotNil(read, "the stream went away before its FIN was read")
        XCTAssertTrue(finished)
        pair.clientEvents += LockstepPair.events(&pair.client)
        XCTAssertTrue(pair.clientEvents.contains(.streamClosed(id)), "\(pair.clientEvents)")
        XCTAssertFalse(pair.client.hasStream(id))
    }

    func testAPacketThatCantBeOpenedDoesNotDropThePacketsCoalescedAfterIt() {
        var pair = self.connectedPair()
        pair.client.injectedFrames.append([0x1a] + [UInt8](repeating: 5, count: 8))  // PATH_CHALLENGE
        let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertEqual(datagrams.count, 1)
        // A Handshake packet whose keys the server has dropped, coalesced in front of the 1-RTT one.
        let destination = [UInt8](repeating: 0, count: 8)
        let handshakePacket: [UInt8] =
            [0xe1, 0x00, 0x00, 0x00, 0x01, UInt8(destination.count)] + destination + [0]
            + Frame.vle(40) + [UInt8](repeating: 0x5a, count: 40)
        var datagram = handshakePacket + datagrams[0]
        let now = pair.now
        let pending: [UInt64] =
            pair.withServer { server in
                var span = datagram.mutableSpan
                server.receive(&span, now: now)
                return server.paths[.initial]?.pendingResponses ?? []
            } ?? []
        XCTAssertEqual(pending, [0x0505_0505_0505_0505])
        XCTAssertNil(pair.server?.closeReason)
    }

    func testResetStreamIsReportedOnce() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, [1, 2, 3]))
        pair.sendFromServer(Frame.resetStream(serverBidirectional, errorCode: 9, finalSize: 3))
        pair.sendFromServer(Frame.resetStream(serverBidirectional, errorCode: 9, finalSize: 3))
        XCTAssertNil(pair.client.closeReason)
        let resets = pair.clientEvents.filter { $0 == .streamReset(serverBidirectional, errorCode: 9) }
        XCTAssertEqual(resets.count, 1, "client events: \(pair.clientEvents)")
    }

    func testTooManyStreamsInMaxStreamsIsAFrameEncodingError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.maxStreams(bidirectional: true, (1 << 60) + 1))
        self.assertClientCloses(with: TransportErrorCode.frameEncoding, &pair)
    }

    func testStreamOffsetPastTheMaximumIsAnError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.stream(serverBidirectional, offset: (1 << 62) - 1, [1, 2]))
        // RFC 9000 § 19.8 allows either error.
        let code = transportErrorCode(pair.client.closeReason)
        XCTAssertTrue(
            code == TransportErrorCode.frameEncoding || code == TransportErrorCode.flowControl,
            "client close reason: \(String(describing: pair.client.closeReason))"
        )
    }

    func testHandshakeDoneFromTheClientIsAProtocolViolation() {
        var pair = self.connectedPair()
        pair.sendFromClient(Frame.handshakeDone)
        self.assertServerCloses(with: TransportErrorCode.protocolViolation, &pair)
    }

    func testAcknowledgingAnUnsentPacketIsAProtocolViolation() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.ack(largest: 1_000_000))
        self.assertClientCloses(with: TransportErrorCode.protocolViolation, &pair)
    }

    /// The peer controls the ACK Delay field up to 2^62 - 1; scaled by the ack_delay_exponent it
    /// saturates rather than overflowing, and the RTT estimate caps it at max_ack_delay
    /// (RFC 9002 Section 5.3).
    func testAHugeAckDelayDoesNotDisturbTheRTT() {
        for delay: UInt64 in [(1 << 62) - 1, 1 << 50] {
            var pair = self.connectedPair()
            pair.client.injectedFrames.append([0x01])  // PING
            let datagrams = LockstepPair.drain(&pair.client, now: pair.now)
            pair.now = pair.now.advanced(by: .milliseconds(30))
            let now = pair.now
            pair.withServer { server in
                for var datagram in datagrams {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: now)
                }
                let largest = server.acks[.applicationData].largestReceived ?? 0
                server.injectedFrames.append(Frame.ack(largest: largest, delay: delay))
            }
            pair.exchange()
            XCTAssertNil(pair.client.closeReason, "delay \(delay)")
            XCTAssertNil(pair.server?.closeReason, "delay \(delay)")
            XCTAssertLessThan(pair.client.smoothedRTT, .seconds(1), "delay \(delay)")
        }
    }

    /// Acknowledgments in Initial packets aren't delayed, so their ACK Delay is ignored
    /// (RFC 9002 Section 5.3), however large.
    func testAHugeAckDelayInAnInitialPacketIsIgnored() {
        for delay: UInt64 in [(1 << 62) - 1, 1 << 50] {
            var pair = LockstepPair()
            let initials = LockstepPair.drain(&pair.client, now: pair.now)
            let ids = LockstepPair.connectionIDs(ofInitial: initials[0])
            var server = QUICConnectionCore(
                serverWith: pair.serverConfiguration,
                localConnectionID: QUICConnectionID(8),
                originalDestinationConnectionID: ids.destination,
                peerConnectionID: ids.source,
                now: pair.now
            )
            // Acknowledges the client's first Initial, packet 0.
            server.injectFrame(Frame.ack(largest: 0, delay: delay), in: .initial)
            pair.server = consume server
            pair.toServer = initials
            pair.exchange()
            XCTAssertTrue(pair.client.isHandshakeConfirmed, "delay \(delay)")
            XCTAssertNil(pair.client.closeReason, "delay \(delay)")
            XCTAssertLessThan(pair.client.smoothedRTT, .seconds(1), "delay \(delay)")
        }
    }

    /// CRYPTO frames without data, at offsets past what arrived, store nothing and don't break
    /// the handshake, in Initial packets to a server and Handshake packets to a client.
    func testEmptyCryptoFramesDuringTheHandshakeStoreNothing() {
        let frames = (0..<1000).map { Frame.crypto(offset: 100_000 + UInt64($0) * 3, []) }
        var pair = LockstepPair()
        for frame in frames {
            pair.client.injectFrame(frame, in: .initial)
        }
        let initials = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: initials[0])
        var server = QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(8),
            originalDestinationConnectionID: ids.destination,
            peerConnectionID: ids.source,
            now: pair.now
        )
        for frame in frames {
            server.injectFrame(frame, in: .handshake)
        }
        for var datagram in initials {
            var span = datagram.mutableSpan
            server.receive(&span, now: pair.now)
        }
        XCTAssertNil(server.closeReason)
        XCTAssertEqual(server.handshake.receive[.initial].bufferedSegmentCount, 0)
        let toClient = LockstepPair.drain(&server, now: pair.now)
        pair.server = consume server
        for var datagram in toClient {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(pair.client.handshake.receive[.handshake].bufferedSegmentCount, 0)
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testAnUnknownFrameTypeIsAFrameEncodingError() {
        var pair = self.connectedPair()
        pair.sendFromServer(Frame.vle(0x21))
        self.assertClientCloses(with: TransportErrorCode.frameEncoding, &pair)
    }

    func testATruncatedFrameIsAFrameEncodingError() {
        var pair = self.connectedPair()
        // A STREAM frame whose length runs past the end of the packet.
        pair.sendFromServer(Frame.vle(0x0a) + Frame.vle(serverBidirectional) + Frame.vle(1300) + [1])
        self.assertClientCloses(with: TransportErrorCode.frameEncoding, &pair)
    }

    /// RFC 9000 Section 12.4: a frame whose fields run past the end of the packet, or hold values
    /// the frame doesn't allow, is a FRAME_ENCODING_ERROR.
    func testMalformedFramesAreFrameEncodingErrors() {
        let frames: [(String, [UInt8])] = [
            ("CRYPTO past the packet", Frame.vle(0x06) + Frame.vle(0) + Frame.vle(1300) + [1]),
            ("NEW_TOKEN past the packet", Frame.vle(0x07) + Frame.vle(1300) + [1]),
            // RFC 9000 Section 19.7.
            ("NEW_TOKEN without a token", Frame.vle(0x07) + Frame.vle(0)),
            // RFC 9000 Section 19.15: a connection ID of 1 to 20 bytes.
            (
                "NEW_CONNECTION_ID of 21 bytes",
                Frame.vle(0x18) + Frame.vle(1) + Frame.vle(0) + [21] + [UInt8](repeating: 7, count: 21)
                    + [UInt8](repeating: 9, count: 16)
            ),
            (
                "NEW_CONNECTION_ID of 0 bytes",
                Frame.vle(0x18) + Frame.vle(1) + Frame.vle(0) + [0] + [UInt8](repeating: 9, count: 16)
            ),
            ("CONNECTION_CLOSE reason past the packet", Frame.vle(0x1c) + [0, 0] + Frame.vle(1300) + [1]),
            // RFC 9000 Section 19.3.1: the first range is larger than the largest acknowledged.
            ("ACK below packet number 0", Frame.vle(0x02) + [1, 0, 0, 2]),
        ]
        for (name, frame) in frames {
            var pair = self.connectedPair()
            pair.sendFromServer(frame)
            XCTAssertEqual(transportErrorCode(pair.client.closeReason), TransportErrorCode.frameEncoding, name)
        }
    }

    /// RFC 9000 Section 19.7: only servers send NEW_TOKEN.
    func testNewTokenFromTheClientIsAProtocolViolation() {
        var pair = self.connectedPair()
        pair.sendFromClient(Frame.vle(0x07) + Frame.vle(4) + [1, 2, 3, 4])
        self.assertServerCloses(with: TransportErrorCode.protocolViolation, &pair)
    }

    func testFramesWithoutStateChangesAreAccepted() {
        var pair = self.connectedPair()
        pair.sendFromServer(
            [0x00, 0x00],  // PADDING
            [0x01],  // PING
            Frame.vle(0x14) + Frame.vle(10),  // DATA_BLOCKED
            Frame.vle(0x15) + Frame.vle(serverBidirectional) + Frame.vle(10),  // STREAM_DATA_BLOCKED
            Frame.vle(0x16) + Frame.vle(10),  // STREAMS_BLOCKED
            Frame.vle(0x17) + Frame.vle(10),  // STREAMS_BLOCKED
            Frame.vle(0x18) + Frame.vle(1) + Frame.vle(0) + [8] + [UInt8](repeating: 7, count: 8)
                + [UInt8](repeating: 9, count: 16),  // NEW_CONNECTION_ID
            // RETIRE_CONNECTION_ID changes state: QUICConnectionCoreConnectionIDTests covers it.
            [0x1b] + [UInt8](repeating: 3, count: 8),  // PATH_RESPONSE
            Frame.vle(0x07) + Frame.vle(4) + [1, 2, 3, 4]  // NEW_TOKEN
        )
        XCTAssertNil(pair.client.closeReason)
        XCTAssertNil(pair.server?.closeReason)
    }

    func testPathChallengeIsAnsweredWithTheSameData() {
        var pair = self.connectedPair()
        let data: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        pair.client.injectedFrames.append([0x1a] + data)
        // Deliver the challenge, but look at the server's answer before the client gets it.
        let challenge = LockstepPair.drain(&pair.client, now: pair.now)
        let now = pair.now
        let answer: [[UInt8]] =
            pair.withServer { server in
                for var datagram in challenge {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: now)
                }
                XCTAssertEqual(server.paths[.initial]?.pendingResponses, [UInt64(0x0102_0304_0506_0708)])
                return LockstepPair.drain(&server, now: now)
            } ?? []
        XCTAssertFalse(answer.isEmpty)
        XCTAssertEqual(pair.server?.paths[.initial]?.pendingResponses, [])
        XCTAssertNil(pair.server?.closeReason)
    }

    func testStopSendingIsAnsweredWithResetStream() throws {
        var pair = self.connectedPair()
        let id = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        pair.client.write([UInt8](repeating: 1, count: 10).span.bytes, to: id)
        pair.exchange()
        pair.sendFromServer(Frame.stopSending(id, errorCode: 42))
        XCTAssertNil(pair.client.closeReason)
        XCTAssertTrue(pair.clientEvents.contains(.stopSending(id, errorCode: 42)), "\(pair.clientEvents)")
        XCTAssertTrue(pair.serverEvents.contains(.streamReset(id, errorCode: 42)), "\(pair.serverEvents)")
        // Nothing more is written once the stream is reset.
        XCTAssertEqual(pair.client.write([UInt8](repeating: 1, count: 10).span.bytes, to: id), 0)
    }

    func testDataOnAStreamWeStoppedIsDiscardedButCountsForFlowControl() throws {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 1000
        var pair = self.connectedPair(clientConfiguration: configuration)
        let first: UInt64? =
            pair.withServer { server in
                guard let id = server.openStream(bidirectional: true) else { return nil }
                server.write([UInt8](repeating: 1, count: 100).span.bytes, to: id)
                return id
            } ?? nil
        let id = try XCTUnwrap(first)
        pair.exchange()
        XCTAssertTrue(pair.client.hasStream(id))
        // More data is in flight when the client asks the server to stop.
        let now = pair.now
        let inFlight: [[UInt8]] =
            pair.withServer { server in
                server.write([UInt8](repeating: 1, count: 800).span.bytes, to: id)
                return LockstepPair.drain(&server, now: now)
            } ?? []
        XCTAssertFalse(inFlight.isEmpty)
        pair.client.stopSending(id, errorCode: 5)
        for var datagram in inFlight {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        XCTAssertNil(pair.client.closeReason)
        let read: Int? = pair.client.read(from: id) { bytes, _ in (bytes.byteCount, bytes.byteCount) }
        XCTAssertEqual(read ?? 0, 0, "bytes of a stopped stream must not be readable")
        pair.exchange()
        XCTAssertTrue(pair.serverEvents.contains(.stopSending(id, errorCode: 5)), "\(pair.serverEvents)")
        // The discarded bytes went back to the connection window, so 900 more bytes fit.
        let response = [UInt8](repeating: 2, count: 900)
        let second: UInt64? =
            pair.withServer { server in
                guard let id = server.openStream(bidirectional: true) else { return nil }
                server.write(response.span.bytes, to: id, fin: true)
                return id
            } ?? nil
        let secondID = try XCTUnwrap(second)
        var received = 0
        var finished = false
        for _ in 0..<10 where !finished {
            pair.exchange()
            while true {
                let consumed: Int? = pair.client.read(from: secondID) { bytes, isFinished in
                    received += bytes.byteCount
                    if isFinished { finished = true }
                    return (bytes.byteCount, bytes.byteCount)
                }
                guard let consumed, consumed > 0 else { break }
            }
        }
        XCTAssertNil(pair.client.closeReason)
        XCTAssertEqual(received, response.count)
        XCTAssertTrue(finished)
    }

    func testAClosingEndpointAnswersWithConnectionCloseAgain() {
        var pair = self.connectedPair()
        pair.client.close(errorCode: 3, isApplication: true, reason: "done", now: pair.now)
        // Lose the client's CONNECTION_CLOSE.
        let lost = LockstepPair.drain(&pair.client, now: pair.now)
        XCTAssertFalse(lost.isEmpty)
        XCTAssertNil(pair.server?.closeReason)
        // The server, unaware, sends something; the client answers with CONNECTION_CLOSE again.
        pair.sendFromServer([0x01])
        XCTAssertEqual(pair.server?.closeReason, .peer(errorCode: 3, isApplication: true, reason: "done"))
    }

    func testADrainingEndpointSendsNothing() {
        var pair = self.connectedPair()
        pair.client.close(errorCode: 3, isApplication: true, now: pair.now)
        pair.exchange()
        guard case .peer = pair.server?.closeReason else {
            return XCTFail("server close reason: \(String(describing: pair.server?.closeReason))")
        }
        pair.client.injectedFrames.append([0x01])
        let ping = LockstepPair.drain(&pair.client, now: pair.now)
        let now = pair.now
        let answer =
            pair.withServer { server in
                for var datagram in ping {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: now)
                }
                return LockstepPair.drain(&server, now: now)
            } ?? []
        XCTAssertEqual(answer.count, 0)
    }
}

// MARK: - Impaired networks

/// SplitMix64, so that a failing seed reproduces.
private struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        self.state &+= 0x9e37_79b9_7f4a_7c15
        var z = self.state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }
}

/// Loses, duplicates, corrupts and delays datagrams.
private struct ImpairedNetwork {
    var loss: Double
    var duplication: Double
    var corruption: Double
    var delay: Double
    var generator: SeededGenerator
    private var delayed: [Bool: [[UInt8]]] = [true: [], false: []]
    private(set) var counts = (lost: 0, duplicated: 0, corrupted: 0, delayed: 0)

    init(seed: UInt64, loss: Double, duplication: Double, corruption: Double, delay: Double) {
        self.generator = SeededGenerator(state: seed)
        self.loss = loss
        self.duplication = duplication
        self.corruption = corruption
        self.delay = delay
    }

    var hasDelayed: Bool {
        !self.delayed[true]!.isEmpty || !self.delayed[false]!.isEmpty
    }

    private mutating func chance(_ probability: Double) -> Bool {
        Double.random(in: 0..<1, using: &self.generator) < probability
    }

    /// The datagrams arriving now: earlier delayed ones, then what survives of `datagrams`.
    mutating func transmit(_ datagrams: [[UInt8]], toServer: Bool) -> [[UInt8]] {
        var arriving = self.delayed[toServer]!
        self.delayed[toServer] = []
        for var datagram in datagrams {
            if self.chance(self.loss) {
                self.counts.lost += 1
                continue
            }
            if self.chance(self.corruption) {
                let index = Int.random(in: 0..<datagram.count, using: &self.generator)
                datagram[index] ^= UInt8.random(in: 1...255, using: &self.generator)
                self.counts.corrupted += 1
            }
            if self.chance(self.duplication) {
                arriving.append(datagram)
                self.counts.duplicated += 1
            }
            if self.chance(self.delay) {
                // Arrives after the next datagrams in this direction: reordered.
                self.delayed[toServer]!.append(datagram)
                self.counts.delayed += 1
            } else {
                arriving.append(datagram)
            }
        }
        return arriving
    }
}

/// What the client does with a stream, and what both sides expect to see.
private enum StreamPlan {
    /// The client sends a request; the server echoes it.
    case echo
    /// The client resets the stream after sending part of the request; the server resets its side.
    case clientResets
    /// The server asks the client to stop sending; the client answers with a reset unless it
    /// already finished; the server then finishes an empty response.
    case serverStopsSending
}

@available(Network 0.1.0, *)
final class QUICConnectionCoreImpairedNetworkTests: XCTestCase {
    private static func payload(for id: UInt64, size: Int) -> [UInt8] {
        (0..<size).map { UInt8(truncatingIfNeeded: Int(id) &* 31 &+ $0 &* 7 &+ $0 >> 8) }
    }

    /// Reads everything readable. Returns whether the peer's FIN was reached.
    private static func readAll(_ core: inout QUICConnectionCore, _ id: UInt64, into buffer: inout [UInt8]) -> Bool {
        var finished = false
        while true {
            let consumed: Int? = core.read(from: id) { bytes, isFinished in
                buffer += [UInt8](copying: bytes)
                if isFinished { finished = true }
                return (bytes.byteCount, bytes.byteCount)
            }
            guard let consumed, consumed > 0 else { break }
        }
        return finished
    }

    private struct ServerStream {
        var received: [UInt8] = []
        var responded = false
        var stopped = false
        var resetSeen = false
    }

    private struct ClientStream {
        var plan: StreamPlan
        var request: [UInt8]
        var response: [UInt8] = []
        var finished = false
    }

    /// Runs one connection with many streams over an impaired network and checks every byte and
    /// every event the plans promise, then that both sides forget every stream.
    /// `keyUpdateEvery` rounds, one side (alternating) tries to update its keys. Returns how many
    /// updates started.
    @discardableResult
    private func run(
        seed: UInt64,
        loss: Double,
        duplication: Double,
        corruption: Double,
        delay: Double,
        keyUpdateEvery: Int = 0
    ) -> Int {
        var network = ImpairedNetwork(
            seed: seed,
            loss: loss,
            duplication: duplication,
            corruption: corruption,
            delay: delay
        )
        let context = "seed \(seed), loss \(loss), duplication \(duplication), corruption \(corruption), delay \(delay)"
        // Small windows, so both sides depend on MAX_DATA and MAX_STREAMS updates getting through.
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.initialMaxData = 64 * 1024
        configuration.initialMaxStreamsBidirectional = 6
        var pair = LockstepPair(clientConfiguration: configuration, serverConfiguration: configuration)
        let sizes = [0, 1, 1200, 5000, 70_000, 300_000, 17, 2900]
        let streamCount = 24
        var clientStreams: [UInt64: ClientStream] = [:]
        var serverStreams: [UInt64: ServerStream] = [:]
        var clientResetsSent = Set<UInt64>()

        var keyUpdates = 0
        var round = 0
        var done = false
        // What the client sent after the last round's receive; it goes out first next round.
        var carried: [[UInt8]] = []
        while round < 50_000 && !done {
            round += 1
            pair.now = pair.now.advanced(by: .milliseconds(1))
            let now = pair.now
            if let deadline = pair.client.nextDeadline, deadline <= now {
                pair.client.handleTimeout(now: now)
            }
            pair.withServer { server in
                if let deadline = server.nextDeadline, deadline <= now {
                    server.handleTimeout(now: now)
                }
            }

            if keyUpdateEvery > 0 && round % keyUpdateEvery == 0 {
                let updated =
                    (round / keyUpdateEvery) % 2 == 0
                    ? pair.client.updateKeys() : (pair.withServer { $0.updateKeys() } ?? false)
                if updated { keyUpdates += 1 }
            }

            // Client to server.
            let fromClient = carried + LockstepPair.drain(&pair.client, now: pair.now)
            carried = []
            if pair.server == nil, let first = fromClient.first {
                let ids = LockstepPair.connectionIDs(ofInitial: first)
                pair.server = QUICConnectionCore(
                    serverWith: pair.serverConfiguration,
                    localConnectionID: QUICConnectionID(8),
                    originalDestinationConnectionID: ids.destination,
                    peerConnectionID: ids.source,
                    now: pair.now
                )
            }
            let toServer = network.transmit(fromClient, toServer: true)
            var fromServer: [[UInt8]] = []
            let newServerEvents: [QUICConnectionCore.Event] =
                pair.withServer { server in
                    for var datagram in toServer {
                        var span = datagram.mutableSpan
                        server.receive(&span, now: now)
                    }
                    let events = LockstepPair.events(&server)
                    // The server application.
                    for event in events {
                        if case .streamReset(let id, _) = event, clientStreams[id]?.plan == .clientResets {
                            serverStreams[id, default: ServerStream()].resetSeen = true
                            // Close our side too, so the stream can go away.
                            server.resetStream(id, errorCode: 0x77)
                        }
                    }
                    for (id, client) in clientStreams where server.hasStream(id) {
                        var stream = serverStreams[id, default: ServerStream()]
                        if client.plan == .serverStopsSending && !stream.stopped {
                            stream.stopped = true
                            server.stopSending(id, errorCode: 0x55)
                        }
                        let finished = Self.readAll(&server, id, into: &stream.received)
                        if !stream.responded && !stream.resetSeen && (finished || stream.stopped) {
                            stream.responded = true
                            let response = client.plan == .echo ? stream.received : []
                            server.write(response.span.bytes, to: id, fin: true)
                        }
                        serverStreams[id] = stream
                    }
                    fromServer = LockstepPair.drain(&server, now: now)
                    return events
                } ?? []
            pair.serverEvents += newServerEvents

            // Server to client.
            for var datagram in network.transmit(fromServer, toServer: false) {
                var span = datagram.mutableSpan
                pair.client.receive(&span, now: pair.now)
            }
            pair.clientEvents += LockstepPair.events(&pair.client)
            // The client application. It opens streams as soon as the server's limit allows, even
            // while the server may still be waiting for the end of the handshake.
            while clientStreams.count < streamCount, pair.client.isHandshakeComplete {
                guard let id = pair.client.openStream(bidirectional: true) else { break }
                let index = clientStreams.count
                let plan: StreamPlan =
                    index % 6 == 4 ? .clientResets : (index % 6 == 5 ? .serverStopsSending : .echo)
                let size = plan == .clientResets ? 20_000 : sizes[index % sizes.count]
                let request = Self.payload(for: id, size: size)
                switch plan {
                case .echo, .serverStopsSending:
                    XCTAssertEqual(pair.client.write(request.span.bytes, to: id, fin: true), request.count)
                case .clientResets:
                    pair.client.write(request.span.bytes, to: id, fin: false)
                }
                clientStreams[id] = ClientStream(plan: plan, request: request)
            }
            for (id, var stream) in clientStreams {
                if stream.plan == .clientResets && pair.client.isHandshakeComplete && !clientResetsSent.contains(id)
                    && round % 7 == Int(id % 7)
                {
                    clientResetsSent.insert(id)
                    pair.client.resetStream(id, errorCode: 0x66)
                }
                if Self.readAll(&pair.client, id, into: &stream.response) {
                    stream.finished = true
                }
                clientStreams[id] = stream
            }

            let allGone =
                clientStreams.count == streamCount
                && clientStreams.keys.allSatisfy { id in
                    !pair.client.hasStream(id) && pair.server?.hasStream(id) == false
                }
            if allGone && clientResetsSent.count == clientStreams.values.filter({ $0.plan == .clientResets }).count {
                done = true
            }
            // Whatever the client can send after this round's receive, such as data a late ACK
            // made room for. Without it, a quiet round would skip ahead to a timer too early.
            carried = LockstepPair.drain(&pair.client, now: pair.now)
            let quiet = fromClient.isEmpty && fromServer.isEmpty && carried.isEmpty && !network.hasDelayed
            if quiet && !done {
                // Nothing in flight; skip to the next timer.
                pair.advanceToNextDeadline()
            }
            if pair.client.closeReason != nil || pair.server?.closeReason != nil {
                break
            }
        }

        XCTAssertNil(pair.client.closeReason, context)
        XCTAssertNil(pair.server?.closeReason, context)
        XCTAssertTrue(done, "streams still open after \(round) rounds, \(context), counts \(network.counts)")

        for (id, stream) in clientStreams.sorted(by: { $0.key < $1.key }) {
            let server = serverStreams[id] ?? ServerStream()
            switch stream.plan {
            case .echo:
                XCTAssertEqual(server.received.count, stream.request.count, "stream \(id) request, \(context)")
                XCTAssertTrue(server.received == stream.request, "stream \(id) request bytes, \(context)")
                XCTAssertTrue(stream.finished, "stream \(id) response FIN, \(context)")
                XCTAssertEqual(stream.response.count, stream.request.count, "stream \(id) response, \(context)")
                XCTAssertTrue(stream.response == stream.request, "stream \(id) response bytes, \(context)")
            case .clientResets:
                XCTAssertTrue(
                    pair.serverEvents.contains(.streamReset(id, errorCode: 0x66)),
                    "stream \(id) reset not seen by the server, \(context)"
                )
                XCTAssertTrue(
                    pair.clientEvents.contains(.streamReset(id, errorCode: 0x77)),
                    "stream \(id) reset not seen by the client, \(context)"
                )
                XCTAssertTrue(
                    stream.request.starts(with: server.received),
                    "stream \(id) received bytes the client never sent, \(context)"
                )
            case .serverStopsSending:
                // STOP_SENDING is moot, and not sent, once the whole request has arrived.
                XCTAssertTrue(
                    pair.clientEvents.contains(.stopSending(id, errorCode: 0x55)) || server.received == stream.request,
                    "stream \(id) STOP_SENDING not seen by the client, \(context)"
                )
                XCTAssertTrue(stream.finished, "stream \(id) response FIN, \(context)")
                XCTAssertEqual(stream.response, [], "stream \(id), \(context)")
            }
            XCTAssertTrue(pair.clientEvents.contains(.streamClosed(id)), "client stream \(id) closed, \(context)")
            XCTAssertTrue(pair.serverEvents.contains(.streamClosed(id)), "server stream \(id) closed, \(context)")
            XCTAssertEqual(
                pair.clientEvents.filter { $0 == .streamOpened(id) }.count,
                0,
                "locally opened stream \(id) reported as opened, \(context)"
            )
            XCTAssertEqual(
                pair.serverEvents.filter { $0 == .streamOpened(id) }.count,
                1,
                "server stream \(id) opened once, \(context)"
            )
        }

        // A graceful close still works afterwards.
        pair.client.close(errorCode: 0, isApplication: true, reason: "", now: pair.now)
        pair.exchange()
        for _ in 0..<5 {
            pair.advanceToNextDeadline()
        }
        XCTAssertEqual(pair.client.closeReason, .local(errorCode: 0, isApplication: true), context)
        XCTAssertEqual(pair.server?.closeReason, .peer(errorCode: 0, isApplication: true, reason: ""), context)
        XCTAssertTrue(pair.client.isClosed, context)
        XCTAssertTrue(pair.server?.isClosed ?? false, context)
        return keyUpdates
    }

    /// Key updates while packets are lost, duplicated, corrupted and reordered across them.
    func testKeyUpdatesOverAnImpairedNetwork() {
        for seed in UInt64(1)...8 {
            let updates = self.run(
                seed: seed,
                loss: 0.1,
                duplication: 0.1,
                corruption: 0.05,
                delay: 0.15,
                keyUpdateEvery: 20
            )
            XCTAssertGreaterThanOrEqual(updates, 2, "seed \(seed)")
        }
    }

    /// Seeds in which the client's Finished is lost while its first 1-RTT packets fill the
    /// congestion window. The server can't acknowledge 1-RTT packets before it has the Finished,
    /// so if the retransmission waited for room in the window, these would stall until the idle
    /// timeout.
    func testLosingTheClientFinishedBehindAFullCongestionWindow() {
        for seed: UInt64 in [66, 67, 104, 130] {
            self.run(seed: seed, loss: 0.1, duplication: 0.1, corruption: 0.05, delay: 0.15)
        }
        for seed: UInt64 in [1063, 1079, 1088, 1105, 1147] {
            self.run(seed: seed, loss: 0.2, duplication: 0, corruption: 0, delay: 0)
        }
    }

    /// A client that sent no 1-RTT data can only learn that the handshake is confirmed from
    /// HANDSHAKE_DONE, so a lost one has to be sent again.
    func testALostHandshakeDoneIsSentAgain() {
        var pair = LockstepPair()
        pair.toServer = LockstepPair.drain(&pair.client, now: pair.now)
        let ids = LockstepPair.connectionIDs(ofInitial: pair.toServer[0])
        pair.server = QUICConnectionCore(
            serverWith: pair.serverConfiguration,
            localConnectionID: QUICConnectionID(8),
            originalDestinationConnectionID: ids.destination,
            peerConnectionID: ids.source,
            now: pair.now
        )
        func deliverToServer(_ datagrams: [[UInt8]], _ pair: inout LockstepPair) -> [[UInt8]] {
            let now = pair.now
            return pair.withServer { server in
                for var datagram in datagrams {
                    var span = datagram.mutableSpan
                    server.receive(&span, now: now)
                }
                return LockstepPair.drain(&server, now: now)
            } ?? []
        }
        let flight = deliverToServer(pair.toServer, &pair)
        pair.toServer = []
        for var datagram in flight {
            var span = datagram.mutableSpan
            pair.client.receive(&span, now: pair.now)
        }
        // The client's Finished confirms the server, whose answer with HANDSHAKE_DONE is lost.
        let finished = LockstepPair.drain(&pair.client, now: pair.now)
        let lost = deliverToServer(finished, &pair)
        XCTAssertTrue(pair.server?.isHandshakeConfirmed ?? false)
        XCTAssertFalse(lost.isEmpty)
        XCTAssertFalse(pair.client.isHandshakeConfirmed)
        for _ in 0..<10 where !pair.client.isHandshakeConfirmed {
            pair.advanceToNextDeadline()
            pair.exchange()
        }
        XCTAssertTrue(pair.client.isHandshakeConfirmed)
        XCTAssertNil(pair.client.closeReason)
    }

    func testAPerfectNetwork() {
        self.run(seed: 1, loss: 0, duplication: 0, corruption: 0, delay: 0)
    }

    func testLoss() {
        for seed in UInt64(1)...8 {
            self.run(seed: seed, loss: 0.15, duplication: 0, corruption: 0, delay: 0)
        }
    }

    func testHeavyLoss() {
        for seed in UInt64(1)...4 {
            self.run(seed: seed, loss: 0.35, duplication: 0, corruption: 0, delay: 0)
        }
    }

    func testDuplication() {
        for seed in UInt64(1)...4 {
            self.run(seed: seed, loss: 0, duplication: 0.3, corruption: 0, delay: 0)
        }
    }

    func testReordering() {
        for seed in UInt64(1)...4 {
            self.run(seed: seed, loss: 0, duplication: 0, corruption: 0, delay: 0.3)
        }
    }

    func testCorruption() {
        for seed in UInt64(1)...4 {
            self.run(seed: seed, loss: 0, duplication: 0, corruption: 0.1, delay: 0)
        }
    }

    func testEverythingAtOnce() {
        for seed in UInt64(1)...16 {
            self.run(seed: seed, loss: 0.1, duplication: 0.1, corruption: 0.05, delay: 0.15)
        }
    }
}

#endif
