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

@_spi(Essentials) @_spi(ProtocolProvider) import QUICStateMachine

#if !NETWORK_NO_SWIFT_QUIC

#if IMPORT_CRYPTO || IMPORT_SWIFTTLS
#if canImport(CryptoKit)
internal import CryptoKit
#elseif canImport(Crypto)
@preconcurrency internal import Crypto
#endif
#endif

#if IMPORT_SWIFTTLS && canImport(SwiftTLS)
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

/// Transport error codes (RFC 9000 Section 20.1).
@available(Network 0.1.0, *)
enum CoreTransportError {
    static let noError: UInt64 = 0x0
    static let internalError: UInt64 = 0x1
    static let flowControlError: UInt64 = 0x3
    static let streamLimitError: UInt64 = 0x4
    static let streamStateError: UInt64 = 0x5
    static let finalSizeError: UInt64 = 0x6
    static let frameEncodingError: UInt64 = 0x7
    static let transportParameterError: UInt64 = 0x8
    static let protocolViolation: UInt64 = 0xa
    static let applicationError: UInt64 = 0xc
    static let cryptoBufferExceeded: UInt64 = 0xd
    static let cryptoError: UInt64 = 0x100
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// Processes one received UDP datagram. Decrypts in place.
    public mutating func receive(_ datagram: inout MutableSpan<UInt8>, now: NetworkClock.Instant) {
        switch self.state {
        case .closed, .draining:
            return
        case .closing:
            // Answer with the CONNECTION_CLOSE again.
            self.closeFrameSentInState = false
            return
        case .handshaking, .established:
            break
        }
        let count = datagram.count
        self.bytesReceived &+= count
        var offset = 0
        while offset < count {
            let consumed = self.receivePacket(in: &datagram, at: offset, now: now)
            guard consumed > 0 else { break }
            offset &+= consumed
            if self.isClosingOrDraining { break }
        }
    }

    /// Decodes, decrypts and processes the packet at `offset`. Returns its length, or zero if the
    /// rest of the datagram can't be parsed.
    private mutating func receivePacket(
        in datagram: inout MutableSpan<UInt8>,
        at offset: Int,
        now: NetworkClock.Instant
    )
        -> Int
    {
        let count = datagram.count
        let context = PacketParser.DecodeContext(
            localCIDLength: self.localConnectionID.length,
            isVersionSent: false,
            isConnected: self.handshake.isComplete,
            connectionKeyState: self.keyPhase,
            keyUpdateThreshold: self.keyPhaseFirstReceived ?? .max
        )
        var region = datagram._mutatingExtracting(offset..<count)
        var bytes = PacketBytes(region._mutatingExtracting(0..<region.count))
        let acks = self.acks
        let outcome = self.parser.decodeAndOpen(
            &bytes,
            context: context,
            largestPacketNumberReceived: { space in
                acks[space].largestReceived.map { PacketNumber(Int64($0)) } ?? .none
            },
            protector: &self.protector
        )
        switch consume outcome {
        case .drop:
            break
        case .packet(let packet):
            // Version negotiation, retry, or a packet we can't decrypt (yet).
            if packet.failedDecryption {
                self.log.debug("Dropping undecryptable packet in \(packet.numberSpace)")
            }
        case .payload(let packet, let extraLength, let reservedBits):
            let packetLength = (count &- offset) &- extraLength
            guard reservedBits == 0 else {
                self.closeWithError(CoreTransportError.protocolViolation, reason: "Reserved bits set", now: now)
                return packetLength
            }
            let space = packet.numberSpace
            let packetNumber = UInt64(packet.number.value)
            if self.acks[space].isDuplicate(packetNumber) {
                return packetLength
            }
            if let packetKeyPhase = packet.keyState, !packet.longHeader {
                self.onKeyPhaseReceived(packetKeyPhase, packetNumber: packetNumber)
            }
            if !self.isServer, !self.receivedFirstServerPacket, packet.longHeader,
                let sourceConnectionID = packet.sourceConnectionID
            {
                // The server picked its own connection ID; use it from now on.
                self.receivedFirstServerPacket = true
                self.peerConnectionID = sourceConnectionID
            }
            let isAckEliciting = self.processFrames(bytes.bytes, in: space, now: now)
            if self.isClosed { return packetLength }
            self.acks[space].onPacketReceived(
                packetNumber,
                isAckEliciting: isAckEliciting,
                immediate: space != .applicationData || !self.handshake.isComplete,
                maxAckDelay: self.configuration.maxAckDelay,
                now: now
            )
            if space == .handshake && self.isServer && !self.addressValidated {
                // A Handshake packet proves the client owns its address.
                self.addressValidated = true
            }
            if space == .handshake && self.isServer {
                self.discardSpace(.initial)
            }
            self.idleDeadline = self.idleTimeout.map { now.advanced(by: $0) }
            return packetLength
        }
        // A packet we can't open, for example one whose keys we already dropped, still says how
        // long it is. The packets coalesced after it may be fine (RFC 9000 Section 12.2).
        return Self.coalescedPacketLength(datagram.span.bytes.extracting(offset..<count)) ?? 0
    }

    /// Follows the peer's key updates. The parser already rotated the keys if `phase` is a new
    /// one; a packet in the previous phase was sent before the update and changes nothing.
    private mutating func onKeyPhaseReceived(_ phase: PacketKeyState, packetNumber: UInt64) {
        if phase == self.keyPhase {
            self.keyPhaseFirstReceived = min(self.keyPhaseFirstReceived ?? packetNumber, packetNumber)
        } else if let first = self.keyPhaseFirstReceived, packetNumber >= first {
            self.keyPhase = phase
            self.keyPhaseFirstReceived = packetNumber
        }
    }

    /// The length of the long header packet at the start of `bytes`, from its Length field, which
    /// header protection leaves readable. `nil` for short headers, Version Negotiation and Retry,
    /// which end the datagram.
    static func coalescedPacketLength(_ bytes: RawSpan) -> Int? {
        var reader = CoreReader(bytes)
        guard let first = reader.uint8(), first & 0x80 != 0, let version = reader.uint32(), version != 0,
            let destinationLength = reader.uint8(), reader.skip(Int(destinationLength)),
            let sourceLength = reader.uint8(), reader.skip(Int(sourceLength))
        else {
            return nil
        }
        let type = (first >> 4) & 0x03
        if type == 0x03 {
            return nil
        }
        if type == 0x00 {
            guard let tokenLength = reader.vle(), tokenLength <= UInt64(reader.remaining),
                reader.skip(Int(tokenLength))
            else {
                return nil
            }
        }
        guard let length = reader.vle(), length <= UInt64(reader.remaining) else {
            return nil
        }
        return reader.offset &+ Int(length)
    }

    /// Processes the frames of a decrypted packet. Returns whether the packet was ack-eliciting.
    private mutating func processFrames(
        _ payload: RawSpan,
        in space: PacketNumberSpace,
        now: NetworkClock.Instant
    )
        -> Bool
    {
        var reader = CoreReader(payload)
        var isAckEliciting = false
        if payload.byteCount == 0 {
            self.closeWithError(CoreTransportError.protocolViolation, reason: "Packet without frames", now: now)
            return false
        }
        while !reader.isAtEnd {
            guard let frameType = reader.vle() else {
                self.closeWithError(CoreTransportError.frameEncodingError, reason: "Truncated frame type", now: now)
                return isAckEliciting
            }
            if frameType != 0x00 && frameType != 0x02 && frameType != 0x03 && frameType != 0x1c && frameType != 0x1d {
                isAckEliciting = true
            }
            if !self.isAllowed(frameType, in: space) {
                self.closeWithError(
                    CoreTransportError.protocolViolation,
                    frameType: frameType,
                    reason: "Frame not allowed in \(space)",
                    now: now
                )
                return isAckEliciting
            }
            let ok = self.processFrame(frameType, reader: &reader, in: space, now: now)
            if !ok {
                if !self.isClosingOrDraining {
                    self.closeWithError(
                        CoreTransportError.frameEncodingError,
                        frameType: frameType,
                        reason: "Malformed frame",
                        now: now
                    )
                }
                return isAckEliciting
            }
            if self.isClosingOrDraining { break }
        }
        return isAckEliciting
    }

    private func isAllowed(_ frameType: UInt64, in space: PacketNumberSpace) -> Bool {
        guard space != .applicationData else { return true }
        // Initial and Handshake packets only carry PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE.
        switch frameType {
        case 0x00, 0x01, 0x02, 0x03, 0x06, 0x1c: return true
        default: return false
        }
    }

    /// Processes one frame. Returns `false` if the frame is malformed.
    private mutating func processFrame(
        _ frameType: UInt64,
        reader: inout CoreReader,
        in space: PacketNumberSpace,
        now: NetworkClock.Instant
    ) -> Bool {
        switch frameType {
        case 0x00:  // PADDING
            while reader.peekUInt8() == 0 {
                _ = reader.uint8()
            }
            return true
        case 0x01:  // PING
            return true
        case 0x02, 0x03:  // ACK
            return self.processAckFrame(reader: &reader, hasECN: frameType == 0x03, in: space, now: now)
        case 0x04:  // RESET_STREAM
            guard let id = reader.vle(), let code = reader.vle(), let finalSize = reader.vle() else { return false }
            return self.processResetStream(id: id, errorCode: code, finalSize: finalSize, now: now)
        case 0x05:  // STOP_SENDING
            guard let id = reader.vle(), let code = reader.vle() else { return false }
            return self.processStopSending(id: id, errorCode: code, now: now)
        case 0x06:  // CRYPTO
            guard let offset = reader.vle(), let length = reader.vle(), let range = reader.range(Int(length)) else {
                return false
            }
            var outputs: [CoreHandshake.Output] = []
            guard
                self.handshake.receive(
                    offset: offset,
                    bytes: reader.bytes.extracting(range),
                    in: space,
                    outputs: &outputs
                )
            else {
                self.closeWithError(CoreTransportError.cryptoBufferExceeded, reason: "Crypto buffer exceeded", now: now)
                return true
            }
            self.apply(outputs, now: now)
            return true
        case 0x07:  // NEW_TOKEN
            guard let length = reader.vle(), reader.skip(Int(length)) else { return false }
            return true
        case 0x08...0x0f:  // STREAM
            return self.processStreamFrame(frameType, reader: &reader, now: now)
        case 0x10:  // MAX_DATA
            guard let maximum = reader.vle() else { return false }
            if maximum > self.sendMaxData {
                self.sendMaxData = maximum
                self.reportWritableStreams()
            }
            return true
        case 0x11:  // MAX_STREAM_DATA
            guard let id = reader.vle(), let maximum = reader.vle() else { return false }
            return self.processMaxStreamData(id: id, maximum: maximum, now: now)
        case 0x12, 0x13:  // MAX_STREAMS
            guard let maximum = reader.vle() else { return false }
            guard maximum <= (1 << 60) else {
                self.closeWithError(CoreTransportError.frameEncodingError, reason: "MAX_STREAMS too large", now: now)
                return true
            }
            if frameType == 0x12 {
                self.streams.peerMaxStreamsBidirectional = max(self.streams.peerMaxStreamsBidirectional, maximum)
            } else {
                self.streams.peerMaxStreamsUnidirectional = max(self.streams.peerMaxStreamsUnidirectional, maximum)
            }
            return true
        case 0x14:  // DATA_BLOCKED
            return reader.vle() != nil
        case 0x15:  // STREAM_DATA_BLOCKED
            return reader.vle() != nil && reader.vle() != nil
        case 0x16, 0x17:  // STREAMS_BLOCKED
            return reader.vle() != nil
        case 0x18:  // NEW_CONNECTION_ID
            guard reader.vle() != nil, reader.vle() != nil, let length = reader.uint8(),
                length >= 1, length <= 20, reader.skip(Int(length)), reader.skip(16)
            else {
                return false
            }
            return true
        case 0x19:  // RETIRE_CONNECTION_ID
            return reader.vle() != nil
        case 0x1a:  // PATH_CHALLENGE
            guard let data = reader.uint64() else { return false }
            self.pendingPathResponses.append(data)
            return true
        case 0x1b:  // PATH_RESPONSE
            return reader.uint64() != nil
        case 0x1c, 0x1d:  // CONNECTION_CLOSE
            guard let code = reader.vle() else { return false }
            if frameType == 0x1c {
                guard reader.vle() != nil else { return false }
            }
            guard let length = reader.vle(), let reasonBytes = reader.array(Int(length)) else { return false }
            let reason = String(decoding: reasonBytes, as: UTF8.self)
            self.closeReason = .peer(errorCode: code, isApplication: frameType == 0x1d, reason: reason)
            self.enterDrainingFromPeer(now: now)
            return true
        case 0x1e:  // HANDSHAKE_DONE
            if self.isServer {
                self.closeWithError(
                    CoreTransportError.protocolViolation,
                    reason: "HANDSHAKE_DONE from client",
                    now: now
                )
                return true
            }
            self.confirmHandshake()
            return true
        case 0x30, 0x31:  // DATAGRAM
            if frameType == 0x31 {
                guard let length = reader.vle(), reader.skip(Int(length)) else { return false }
            } else {
                _ = reader.skip(reader.remaining)
            }
            return true
        default:
            self.closeWithError(
                CoreTransportError.frameEncodingError,
                frameType: frameType,
                reason: "Unknown frame",
                now: now
            )
            return true
        }
    }

    private mutating func enterDrainingFromPeer(now: NetworkClock.Instant) {
        let pto = self.recovery.probeTimeout(includingMaxAckDelay: true)
        self.state = .draining(until: now.advanced(by: pto * 3))
    }

    // MARK: ACK

    private mutating func processAckFrame(
        reader: inout CoreReader,
        hasECN: Bool,
        in space: PacketNumberSpace,
        now: NetworkClock.Instant
    ) -> Bool {
        guard let largest = reader.vle(), let ackDelay = reader.vle(), let rangeCount = reader.vle(),
            let firstRange = reader.vle(), firstRange <= largest
        else {
            return false
        }
        var ranges: [ClosedRange<UInt64>] = [(largest &- firstRange)...largest]
        var smallest = largest &- firstRange
        var index: UInt64 = 0
        while index < rangeCount {
            guard let gap = reader.vle(), let length = reader.vle() else { return false }
            guard smallest >= gap &+ 2 else { return false }
            let upper = smallest &- gap &- 2
            guard upper >= length else { return false }
            ranges.append((upper &- length)...upper)
            smallest = upper &- length
            index &+= 1
        }
        if hasECN {
            guard reader.vle() != nil, reader.vle() != nil, reader.vle() != nil else { return false }
        }
        // Acknowledging a packet we never sent is a protocol violation.
        let nextPacketNumber = UInt64(self.protector.getPacketNumber(for: space).value)
        guard largest < nextPacketNumber else {
            self.closeWithError(CoreTransportError.protocolViolation, reason: "ACK of unsent packet", now: now)
            return true
        }
        let exponent = self.peerTransportParameters?.intValue(.ackDelayExponent) ?? 3
        let delay = NetworkDuration.microseconds(ackDelay << UInt64(exponent))
        let result = self.recovery.onAckReceived(
            ranges: ranges,
            ackDelay: delay,
            in: space,
            handshakeConfirmed: self.isHandshakeConfirmed,
            now: now
        )
        for packet in result.acknowledged {
            self.onPacketAcknowledged(packet, in: space)
        }
        for packet in result.lost {
            self.onPacketLost(packet, in: space)
        }
        return true
    }

    mutating func onPacketAcknowledged(_ packet: CoreSentPacket, in space: PacketNumberSpace) {
        for frame in packet.frames {
            switch frame {
            case .ack(let largestAcknowledged):
                self.acks[space].onAckAcknowledged(largest: largestAcknowledged)
            case .crypto(let offset, let length):
                self.handshake.send[space].onAcked(offset: offset, length: length, fin: false)
            case .stream(let id, let offset, let length, let fin):
                guard var stream = self.streams.streams.removeValue(forKey: id) else { continue }
                let wasFullyAcknowledged = stream.send.isFullyAcknowledged
                stream.send.onAcked(offset: offset, length: length, fin: fin)
                if !wasFullyAcknowledged && stream.send.isFullyAcknowledged {
                    self.events.append(.streamFinishedSending(id))
                }
                self.storeOrRemove(stream)
            case .resetStream(let id):
                guard var stream = self.streams.streams.removeValue(forKey: id) else { continue }
                stream.resetAcknowledged = true
                self.storeOrRemove(stream)
            case .handshakeDone, .maxData, .maxStreamData, .maxStreamsBidirectional, .maxStreamsUnidirectional,
                .stopSending, .dataBlocked, .streamDataBlocked, .newConnectionID, .retireConnectionID, .pathResponse,
                .ping, .datagram:
                break
            }
        }
    }

    mutating func onPacketLost(_ packet: CoreSentPacket, in space: PacketNumberSpace) {
        for frame in packet.frames {
            switch frame {
            case .ack:
                break
            case .crypto(let offset, let length):
                self.handshake.send[space].onLost(offset: offset, length: length, fin: false)
            case .stream(let id, let offset, let length, let fin):
                // Mutated in place: a copy would duplicate the stream's buffers.
                guard self.streams.streams[id]?.resetCode == nil, self.streams.streams[id] != nil else { continue }
                self.streams.streams[id]!.send.onLost(offset: offset, length: length, fin: fin)
                self.streams.enqueueForSending(id)
            case .resetStream(let id):
                guard self.streams.streams[id] != nil else { continue }
                self.streams.streams[id]!.resetPending = true
                self.streams.enqueueForSending(id)
            case .stopSending(let id):
                guard self.streams.streams[id] != nil, self.streams.streams[id]!.peerResetCode == nil else { continue }
                self.streams.streams[id]!.stopSendingPending = true
                self.streams.enqueueForSending(id)
            case .maxData:
                self.maxDataPending = true
            case .maxStreamData(let id):
                guard self.streams.streams[id] != nil, self.streams.streams[id]!.receive.finalSize == nil else {
                    continue
                }
                self.streams.streams[id]!.maxStreamDataPending = true
                self.streams.enqueueForSending(id)
            case .maxStreamsBidirectional:
                self.streams.maxStreamsBidirectionalPending = true
            case .maxStreamsUnidirectional:
                self.streams.maxStreamsUnidirectionalPending = true
            case .handshakeDone:
                self.handshakeDonePending = true
            case .dataBlocked, .streamDataBlocked, .newConnectionID, .retireConnectionID, .pathResponse, .ping,
                .datagram:
                break
            }
        }
    }

    /// Queues the unacknowledged CRYPTO data of `space` for retransmission, for a PTO probe.
    mutating func requeueUnacknowledgedCrypto(in space: PacketNumberSpace) {
        for packet in self.recovery.spaces[Int(space.rawValue)].sent {
            for frame in packet.frames {
                if case .crypto(let offset, let length) = frame {
                    self.handshake.send[space].onLost(offset: offset, length: length, fin: false)
                }
            }
        }
    }

    // MARK: Streams

    private mutating func processStreamFrame(
        _ frameType: UInt64,
        reader: inout CoreReader,
        now: NetworkClock.Instant
    )
        -> Bool
    {
        guard let id = reader.vle() else { return false }
        var offset: UInt64 = 0
        if frameType & 0x04 != 0 {
            guard let value = reader.vle() else { return false }
            offset = value
        }
        let length: Int
        if frameType & 0x02 != 0 {
            guard let value = reader.vle() else { return false }
            length = Int(value)
        } else {
            length = reader.remaining
        }
        guard let range = reader.range(length) else { return false }
        let fin = frameType & 0x01 != 0
        guard offset &+ UInt64(length) < (1 << 62) else {
            self.closeWithError(CoreTransportError.frameEncodingError, reason: "Stream offset too large", now: now)
            return true
        }
        guard var stream = self.stream(forReceiving: id, now: now) else {
            return true
        }
        guard stream.canReceive else {
            self.closeWithError(CoreTransportError.streamStateError, reason: "STREAM on send-only stream", now: now)
            return true
        }
        let previousHighest = stream.receive.highestOffset
        let end = offset &+ UInt64(length)
        if end > stream.receiveLimit {
            self.closeWithError(CoreTransportError.flowControlError, reason: "Stream flow control", now: now)
            return true
        }
        if end > previousHighest {
            self.receivedData &+= end &- previousHighest
            if self.receivedData > self.receiveMaxData {
                self.closeWithError(CoreTransportError.flowControlError, reason: "Connection flow control", now: now)
                return true
            }
        }
        if stream.stopSendingCode != nil {
            // We asked the peer to stop; count the bytes for flow control and drop them.
            do {
                try stream.receive.insert(offset: offset, bytes: reader.bytes.extracting(range), fin: fin)
            } catch {
                self.closeWithError(CoreTransportError.finalSizeError, reason: "Final size", now: now)
                return true
            }
            self.consumedData &+= stream.receive.discard()
            self.storeOrRemove(stream)
            return true
        }
        let readable: Int
        do {
            readable = try stream.receive.insert(offset: offset, bytes: reader.bytes.extracting(range), fin: fin)
        } catch {
            self.closeWithError(CoreTransportError.finalSizeError, reason: "Final size", now: now)
            return true
        }
        if (readable > 0 || stream.receive.isComplete) && !stream.readableReported {
            stream.readableReported = true
            self.events.append(.streamReadable(id))
        }
        self.streams.streams[id] = stream
        return true
    }

    /// The stream a receive-side frame refers to, opening peer streams as needed. Returns `nil`
    /// for a closed stream, or after closing the connection on an invalid stream.
    private mutating func stream(forReceiving id: UInt64, now: NetworkClock.Instant) -> CoreStream? {
        if let stream = self.streams.streams[id] {
            return stream
        }
        if self.streams.isUnopenedLocal(id) {
            self.closeWithError(CoreTransportError.streamStateError, reason: "Frame for unopened stream", now: now)
            return nil
        }
        if self.streams.wasClosed(id) {
            return nil
        }
        do {
            let peerParameters = self.peerTransportParameters
            let configuration = self.configuration
            let opened = try self.streams.openRemote(
                upTo: id,
                sendLimit: { bidirectional in
                    UInt64(peerParameters?.intValue(.initialMaxStreamDataBidirectionalLocal) ?? 0)
                },
                receiveWindow: { bidirectional in
                    bidirectional
                        ? configuration.initialMaxStreamDataBidirectionalRemote
                        : configuration.initialMaxStreamDataUnidirectional
                }
            )
            for openedID in opened {
                self.events.append(.streamOpened(openedID))
            }
        } catch {
            self.closeWithError(CoreTransportError.streamLimitError, reason: "Stream limit", now: now)
            return nil
        }
        return self.streams.streams[id]
    }

    private mutating func processResetStream(
        id: UInt64,
        errorCode: UInt64,
        finalSize: UInt64,
        now: NetworkClock.Instant
    )
        -> Bool
    {
        guard var stream = self.stream(forReceiving: id, now: now) else { return true }
        guard stream.canReceive else {
            self.closeWithError(
                CoreTransportError.streamStateError,
                reason: "RESET_STREAM on send-only stream",
                now: now
            )
            return true
        }
        let previousHighest = stream.receive.highestOffset
        do {
            try stream.receive.reset(finalSize: finalSize)
        } catch {
            self.closeWithError(CoreTransportError.finalSizeError, reason: "Final size", now: now)
            return true
        }
        // The final size counts against flow control like data would (RFC 9000 § 4.5).
        if finalSize > stream.receiveLimit {
            self.closeWithError(CoreTransportError.flowControlError, reason: "Stream flow control", now: now)
            return true
        }
        if finalSize > previousHighest {
            self.receivedData &+= finalSize &- previousHighest
            if self.receivedData > self.receiveMaxData {
                self.closeWithError(CoreTransportError.flowControlError, reason: "Connection flow control", now: now)
                return true
            }
        }
        let wasReset = stream.peerResetCode != nil
        stream.peerResetCode = errorCode
        self.consumedData &+= stream.receive.discard()
        self.updateConnectionReceiveLimit()
        if !wasReset {
            self.events.append(.streamReset(id, errorCode: errorCode))
        }
        self.storeOrRemove(stream)
        return true
    }

    private mutating func processStopSending(id: UInt64, errorCode: UInt64, now: NetworkClock.Instant) -> Bool {
        if self.streams.streams[id] == nil && !self.streams.isLocal(id) {
            _ = self.stream(forReceiving: id, now: now)
        } else if self.streams.isUnopenedLocal(id) {
            self.closeWithError(
                CoreTransportError.streamStateError,
                reason: "STOP_SENDING for unopened stream",
                now: now
            )
            return true
        }
        guard var stream = self.streams.streams[id] else { return true }
        guard stream.canSend else {
            self.closeWithError(
                CoreTransportError.streamStateError,
                reason: "STOP_SENDING on receive-only stream",
                now: now
            )
            return true
        }
        if stream.peerStopSendingCode == nil {
            stream.peerStopSendingCode = errorCode
            self.events.append(.stopSending(id, errorCode: errorCode))
        }
        // Answer with RESET_STREAM unless everything was already sent and acknowledged.
        if stream.resetCode == nil && !stream.send.isFullyAcknowledged {
            stream.resetCode = errorCode
            stream.resetPending = true
            self.streams.enqueueForSending(id)
        }
        self.streams.streams[id] = stream
        return true
    }

    private mutating func processMaxStreamData(id: UInt64, maximum: UInt64, now: NetworkClock.Instant) -> Bool {
        if self.streams.streams[id] == nil && !self.streams.isLocal(id) {
            _ = self.stream(forReceiving: id, now: now)
        } else if self.streams.isUnopenedLocal(id) {
            self.closeWithError(
                CoreTransportError.streamStateError,
                reason: "MAX_STREAM_DATA for unopened stream",
                now: now
            )
            return true
        }
        guard var stream = self.streams.streams[id] else { return true }
        guard stream.canSend else {
            self.closeWithError(
                CoreTransportError.streamStateError,
                reason: "MAX_STREAM_DATA on receive-only stream",
                now: now
            )
            return true
        }
        if maximum > stream.sendLimit {
            stream.sendLimit = maximum
            if stream.writableBlocked {
                stream.writableBlocked = false
                self.events.append(.streamWritable(id))
            }
            if stream.hasPendingFrames {
                self.streams.enqueueForSending(id)
            }
        }
        self.streams.streams[id] = stream
        return true
    }

    private mutating func reportWritableStreams() {
        for (id, stream) in self.streams.streams where stream.hasPendingFrames {
            self.streams.enqueueForSending(id)
        }
    }

    // MARK: Handshake

    mutating func apply(_ outputs: [CoreHandshake.Output], now: NetworkClock.Instant) {
        for output in outputs {
            switch output {
            case .secret(let level, let secret, let isWrite, let cipherSuite):
                guard let tlsCipherSuite = TLSCipherSuite(sslCipherSuite: cipherSuite) else { continue }
                self.protector.keyUpdate(
                    for: TLSEncryptionLevel(level),
                    cipherSuite: tlsCipherSuite,
                    secret: SymmetricKey(data: secret),
                    isWrite: isWrite
                )
            case .peerTransportParameters(let bytes, let earlyData):
                guard !earlyData || self.peerTransportParameters == nil else { continue }
                self.setPeerTransportParameters(bytes, now: now)
            case .earlyDataAccepted:
                break
            case .sessionTickets:
                break
            case .complete:
                self.state = .established
                self.events.append(.connected)
                if self.isServer {
                    // The server confirms the handshake as soon as it completes.
                    self.handshakeDonePending = true
                    self.confirmHandshake()
                }
            case .failed(let code):
                self.closeWithError(
                    CoreTransportError.cryptoError,
                    reason: "TLS handshake failed (\(code))",
                    now: now
                )
            }
        }
    }

    private mutating func setPeerTransportParameters(_ bytes: [UInt8], now: NetworkClock.Instant) {
        let parameters: TransportParameters
        do {
            parameters = try TransportParameters.deserialize(bytes.span, logPrefixer: self.log)
        } catch {
            self.closeWithError(
                CoreTransportError.transportParameterError,
                reason: "Invalid transport parameters",
                now: now
            )
            return
        }
        self.peerTransportParameters = parameters
        self.sendMaxData = UInt64(parameters.intValue(.initialMaxData))
        self.streams.peerMaxStreamsBidirectional = UInt64(parameters.intValue(.initialMaxStreamsBidirectional))
        self.streams.peerMaxStreamsUnidirectional = UInt64(parameters.intValue(.initialMaxStreamsUnidirectional))
        let peerIdle = NetworkDuration.milliseconds(parameters.intValue(.maxIdleTimeout))
        if peerIdle > .zero, self.idleTimeout.map({ peerIdle < $0 }) ?? true {
            self.idleTimeout = peerIdle
            let deadline = now.advanced(by: peerIdle)
            if self.idleDeadline.map({ deadline < $0 }) ?? true {
                self.idleDeadline = deadline
            }
        }
        // max_ack_delay is a duration; `intValue` traps on it.
        self.recovery.maxAckDelay = parameters[.maxAckDelay]?.duration ?? .milliseconds(25)
        // Streams opened before the parameters arrived get their limits now.
        for (id, var stream) in self.streams.streams where stream.canSend && stream.sendLimit == 0 {
            stream.sendLimit =
                CoreStreamMap.isBidirectional(id)
                ? UInt64(parameters.intValue(.initialMaxStreamDataBidirectionalRemote))
                : UInt64(parameters.intValue(.initialMaxStreamDataUnidirectional))
            self.streams.streams[id] = stream
        }
    }

    #if canImport(SwiftTLS) && SWIFTTLS_CERTIFICATE_VERIFICATION
    /// Installs the handler SwiftTLS calls when an asynchronous step, such as certificate
    /// verification, finishes. The handler runs on an arbitrary thread; the driver hops back to its
    /// own and calls ``resumeHandshake(with:now:)``.
    public func setAsyncContinuationHandler(_ handler: (@Sendable (PendingAsyncResult) -> Void)?) {
        self.handshake.setAsyncContinuationHandler(handler)
    }

    /// Continues the handshake with the result of an asynchronous step.
    public mutating func resumeHandshake(with result: PendingAsyncResult, now: NetworkClock.Instant) {
        guard !self.isClosingOrDraining else { return }
        self.handshake.setAsyncResult(result)
        var outputs: [CoreHandshake.Output] = []
        self.handshake.resume(outputs: &outputs)
        self.apply(outputs, now: now)
    }
    #endif

    mutating func confirmHandshake() {
        guard !self.isHandshakeConfirmed else { return }
        self.isHandshakeConfirmed = true
        self.discardSpace(.initial)
        self.discardSpace(.handshake)
        self.handshake.release()
    }

    mutating func discardSpace(_ space: PacketNumberSpace) {
        let index = Int(space.rawValue)
        guard !self.spaceDiscarded[index] else { return }
        self.spaceDiscarded[index] = true
        self.recovery.discard(space)
        self.acks[space] = CoreAckTracker()
        self.probesPending[index] = 0
        switch space {
        case .initial: self.protector.drop(keyState: .initial)
        case .handshake: self.protector.drop(keyState: .handshake)
        case .applicationData: break
        }
    }
}

#endif
