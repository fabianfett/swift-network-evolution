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

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    static let tagLength = 16
    static let minimumInitialDatagramSize = 1200

    /// Writes the next datagram to send on the active path into `buffer`. Returns its length, or
    /// `nil` if there is nothing to send right now.
    public mutating func send(into buffer: inout MutableSpan<UInt8>, now: NetworkClock.Instant) -> Int? {
        self.send(into: &buffer, on: self.activePath, now: now)
    }

    /// Writes the next datagram to send on `path` into `buffer`. On a path other than the active
    /// one, that is only PATH_CHALLENGE and PATH_RESPONSE; ``pathWithProbeToSend`` says where.
    public mutating func send(
        into buffer: inout MutableSpan<UInt8>,
        on path: CorePathID,
        now: NetworkClock.Instant
    ) -> Int? {
        guard path == self.activePath else {
            return self.sendProbe(into: &buffer, on: path, now: now)
        }
        guard let length = self.sendOnActivePath(into: &buffer, now: now) else { return nil }
        self.paths[path]?.bytesSent &+= length
        return length
    }

    private mutating func sendProbe(
        into buffer: inout MutableSpan<UInt8>,
        on path: CorePathID,
        now: NetworkClock.Instant
    ) -> Int? {
        guard case .established = self.state, self.paths[path]?.hasProbingFramesToSend == true,
            self.assignPeerConnectionID(to: path), self.peerConnectionID(on: path) != nil
        else {
            return nil
        }
        let limit = min(buffer.count, self.configuration.maxDatagramSize, self.amplificationBudget(on: path))
        guard limit > 64 else { return nil }
        guard
            let length = self.writePacket(
                in: .applicationData,
                into: &buffer,
                at: 0,
                maximumLength: limit,
                padDatagramTo: min(Self.minimumInitialDatagramSize, limit),
                congestionLimited: false,
                probing: path,
                now: now
            )
        else {
            return nil
        }
        self.paths[path]?.bytesSent &+= length
        return length
    }

    private mutating func sendOnActivePath(into buffer: inout MutableSpan<UInt8>, now: NetworkClock.Instant) -> Int? {
        switch self.state {
        case .closed, .draining:
            return nil
        case .closing:
            return self.sendClose(into: &buffer, now: now)
        case .handshaking, .established:
            break
        }

        var limit = min(buffer.count, self.configuration.maxDatagramSize)
        if self.isServer && !self.addressValidated {
            // Anti-amplification: at most three times what the client sent.
            let budget = 3 &* self.bytesReceived &- self.bytesSent
            guard budget > 0 else { return nil }
            limit = min(limit, budget)
        }
        if self.activePath != .initial {
            // The same holds on a path the client moved to, until it is validated.
            let budget = self.amplificationBudget(on: self.activePath)
            guard budget > 0 else { return nil }
            limit = min(limit, budget)
        }

        let congestionLimited = self.recovery.availableCongestionWindow <= 0
        var spaces: [PacketNumberSpace] = []
        for space in PacketNumberSpace.allCases where self.wantsToSend(in: space, congestionLimited: congestionLimited)
        {
            spaces.append(space)
        }
        guard !spaces.isEmpty else { return nil }

        // A datagram with an ack-eliciting Initial packet is padded to 1200 bytes, or the size
        // the client is configured with.
        let padsInitial =
            spaces.first == .initial && (!self.isServer || self.handshake.send[PacketNumberSpace.initial].hasDataToSend)
        let initialDatagramSize = max(Self.minimumInitialDatagramSize, self.configuration.initialDatagramSize)
        if padsInitial && limit < Self.minimumInitialDatagramSize {
            return nil
        }

        var offset = 0
        var sentHandshake = false
        for (index, space) in spaces.enumerated() {
            let isLast = index == spaces.count &- 1
            let padTo = (padsInitial && isLast) ? min(initialDatagramSize, limit) : nil
            guard
                let length = self.writePacket(
                    in: space,
                    into: &buffer,
                    at: offset,
                    maximumLength: limit &- offset,
                    padDatagramTo: padTo,
                    congestionLimited: congestionLimited,
                    now: now
                )
            else {
                continue
            }
            offset &+= length
            if space == .handshake { sentHandshake = true }
            if space == .applicationData { break }
            if limit &- offset < 64 { break }
        }
        guard offset > 0 else { return nil }
        self.bytesSent &+= offset
        if sentHandshake && !self.isServer {
            // A client discards its Initial keys once it sends a Handshake packet.
            self.discardSpace(.initial)
        }
        return offset
    }

    private func wantsToSend(in space: PacketNumberSpace, congestionLimited: Bool) -> Bool {
        let index = Int(space.rawValue)
        guard !self.spaceDiscarded[index] else { return false }
        let keyState: PacketKeyState =
            space == .initial
            ? .initial : (space == .handshake ? .handshake : (self.sendsEarlyData ? .earlyData : self.keyPhase))
        guard self.protector.sealKeyReady(for: keyState) else { return false }
        if self.acks[space].ackNeeded && self.acks[space].hasAckToSend {
            return true
        }
        if self.probesPending[index] > 0 {
            return true
        }
        // Keepalives ignore the congestion window.
        if space == .applicationData && self.keepAlivePending && self.handshake.isComplete {
            return true
        }
        // Handshake data ignores the congestion window: 1-RTT packets sent right after the
        // handshake can fill it, and the peer won't acknowledge them before it has our
        // (possibly lost) Finished. Waiting for room would deadlock.
        if space != .applicationData && self.handshake.send[space].hasDataToSend {
            return true
        }
        if congestionLimited {
            return false
        }
        if self.handshake.send[space].hasDataToSend {
            return true
        }
        if space == .applicationData {
            return self.hasApplicationFramesToSend
        }
        return false
    }

    var hasApplicationFramesToSend: Bool {
        guard self.handshake.isComplete else { return self.canSendEarlyData && self.hasEarlyDataFramesToSend }
        return self.handshakeDonePending || self.keepAlivePending || self.maxDataPending
            || self.streams.maxStreamsBidirectionalPending
            || self.streams.maxStreamsUnidirectionalPending || self.pingPending
            || self.paths[self.activePath]?.hasProbingFramesToSend == true
            || !self.datagramsToSend.isEmpty || self.hasConnectionIDFramesToSend || self.hasSendableStreams
            || self.hasInjectedFrames
    }

    /// Whether 1-RTT data goes out in 0-RTT packets, as the client has no 1-RTT keys yet.
    var sendsEarlyData: Bool {
        self.canSendEarlyData && !self.protector.sealKeyReady(for: self.keyPhase)
    }

    var hasInjectedFrames: Bool {
        #if DEBUG
        return !self.injectedFrames.isEmpty
        #else
        return false
        #endif
    }

    var hasSendableStreams: Bool {
        for id in self.streams.sendQueue {
            guard let stream = self.streams.streams[id] else { continue }
            if stream.resetPending || stream.stopSendingPending || stream.maxStreamDataPending {
                return true
            }
            if stream.send.hasRetransmission { return true }
            if stream.hasPendingFrames && (self.sentData < self.sendMaxData || stream.send.unsentCount == 0) {
                return true
            }
        }
        return false
    }

    /// Counts a CRYPTO frame for the statistics.
    mutating func countCryptoFrame(sent: Bool, in space: PacketNumberSpace, length: Int) {
        let frames: QUICStatistic
        let bytes: QUICStatistic
        switch (space, sent) {
        case (.initial, true): (frames, bytes) = (.txInitialCryptoFrames, .txInitialCryptoBytes)
        case (.handshake, true): (frames, bytes) = (.txHandshakeCryptoFrames, .txHandshakeCryptoBytes)
        case (.applicationData, true): (frames, bytes) = (.tx1RTTCryptoFrames, .tx1RTTCryptoBytes)
        case (.initial, false): (frames, bytes) = (.rxInitialCryptoFrames, .rxInitialCryptoBytes)
        case (.handshake, false): (frames, bytes) = (.rxHandshakeCryptoFrames, .rxHandshakeCryptoBytes)
        case (.applicationData, false): (frames, bytes) = (.rx1RTTCryptoFrames, .rx1RTTCryptoBytes)
        }
        self.statistics.increment(frames)
        self.statistics.increment(bytes, by: length)
    }

    /// The Key Phase bit of a short header (RFC 9000 Section 17.3.1).
    private var keyPhaseBit: UInt8 {
        self.keyPhase == .phase1 ? 0x04 : 0x00
    }

    // MARK: Packets

    /// Writes one packet of `space` at `offset`. Returns its length, or `nil` if nothing was written.
    private mutating func writePacket(
        in space: PacketNumberSpace,
        into buffer: inout MutableSpan<UInt8>,
        at offset: Int,
        maximumLength: Int,
        padDatagramTo: Int?,
        congestionLimited: Bool,
        probing: CorePathID? = nil,
        now: NetworkClock.Instant
    ) -> Int? {
        let isEarlyData = space == .applicationData && probing == nil && self.sendsEarlyData
        let keyState: PacketKeyState =
            space == .initial
            ? .initial : (space == .handshake ? .handshake : (isEarlyData ? .earlyData : self.keyPhase))
        // A probe goes to the connection ID of its path.
        let destination = probing.flatMap { self.peerConnectionID(on: $0) } ?? self.peerConnectionID
        var padDatagramTo = padDatagramTo
        let isLongHeader = space != .applicationData || isEarlyData
        let packetNumber = self.protector.getPacketNumber(for: space)
        let largestAcknowledged = self.recovery.spaces[Int(space.rawValue)].largestAcknowledged
        guard
            let encodedPacketNumber = try? packetNumber.encode(
                lastAcked: largestAcknowledged.map { PacketNumber(Int64($0)) } ?? .none,
                fixedSize: nil
            )
        else {
            return nil
        }
        let packetNumberLength = encodedPacketNumber.size.rawValue
        guard maximumLength > 64 else { return nil }

        var frames: [CoreSentFrame] = []
        var isAckEliciting = false
        var hasPadding = false
        var headerLength = 0
        var lengthFieldOffset = 0
        var payloadEnd = 0

        do {
            var writer = CoreWriter(buffer._mutatingExtracting(offset..<(offset &+ maximumLength)))
            // Header.
            if isLongHeader {
                let type: UInt8 = space == .initial ? 0x00 : (isEarlyData ? 0x01 : 0x02)
                var ok = writer.uint8(0xc0 | (type << 4) | encodedPacketNumber.headerFieldSize)
                ok = ok && writer.uint32(self.version)
                ok = ok && writer.uint8(UInt8(self.peerConnectionID.length))
                ok =
                    ok
                    && writer.bytes(
                        self.peerConnectionID.connectionIDStorage.span.bytes.extracting(
                            0..<self.peerConnectionID.length
                        )
                    )
                ok = ok && writer.uint8(UInt8(self.localConnectionID.length))
                ok =
                    ok
                    && writer.bytes(
                        self.localConnectionID.connectionIDStorage.span.bytes.extracting(
                            0..<self.localConnectionID.length
                        )
                    )
                if space == .initial {
                    ok = ok && writer.vle(UInt64(self.initialToken.count))
                    ok = ok && writer.bytes(self.initialToken.span.bytes)
                }
                lengthFieldOffset = writer.offset
                ok = ok && writer.vle2(0)
                guard ok else { return nil }
            } else {
                let spin: UInt8 = self.spinValue ? 0x20 : 0
                guard writer.uint8(0x40 | spin | self.keyPhaseBit | encodedPacketNumber.headerFieldSize),
                    writer.bytes(destination.connectionIDStorage.span.bytes.extracting(0..<destination.length))
                else {
                    return nil
                }
            }
            headerLength = writer.offset
            guard self.writePacketNumber(encodedPacketNumber, into: &writer) else { return nil }
            let payloadStart = writer.offset
            // The tag goes after the frames.
            let frameLimit = maximumLength &- Self.tagLength
            guard frameLimit > payloadStart else { return nil }

            if let probing {
                // A probe carries only the path's frames; `sendProbe` pads it.
                _ = self.writePathFrames(
                    for: probing,
                    into: &writer,
                    limit: frameLimit,
                    frames: &frames,
                    isAckEliciting: &isAckEliciting,
                    now: now
                )
            }
            // ACK.
            if probing == nil && !isEarlyData && self.acks[space].hasAckToSend {
                let ackLength = self.acks[space].ackFrameLength(now: now, ackDelayExponent: 3)
                // An ACK that isn't due yet stays out when the next datagram needs the room: a
                // datagram as large as fits a packet would otherwise never go out.
                var crowdsOutDatagram = false
                if space == .applicationData, !self.acks[space].ackNeeded, let datagram = self.datagramsToSend.first {
                    let datagramLength = 1 &+ CoreWriter.vleLength(UInt64(datagram.count)) &+ datagram.count
                    crowdsOutDatagram = writer.offset &+ ackLength &+ datagramLength > frameLimit
                }
                if writer.offset &+ ackLength <= frameLimit && !crowdsOutDatagram {
                    if let largest = self.acks[space].writeAck(into: &writer, now: now, ackDelayExponent: 3) {
                        frames.append(.ack(largestAcknowledged: largest))
                        self.acks[space].onAckSent()
                    }
                }
            }

            let mayExceedCongestionWindow =
                self.probesPending[Int(space.rawValue)] > 0 || (space == .applicationData && self.keepAlivePending)
            if probing == nil && (!congestionLimited || mayExceedCongestionWindow || space != .applicationData) {
                // CRYPTO.
                while true {
                    let available = frameLimit &- writer.offset &- 1 &- 8 &- 2
                    guard available > 0,
                        let chunk = self.handshake.send[space].nextChunk(
                            maximumLength: available,
                            flowControlLimit: .max
                        ),
                        chunk.length > 0
                    else {
                        break
                    }
                    guard writer.vle(0x06), writer.vle(chunk.offset), writer.vle(UInt64(chunk.length)),
                        self.handshake.send[space].copy(offset: chunk.offset, length: chunk.length, into: &writer)
                    else {
                        break
                    }
                    let isRetransmission =
                        chunk.offset &+ UInt64(chunk.length) <= self.handshake.send[space].sendOffset
                    self.handshake.send[space].markSent(offset: chunk.offset, length: chunk.length, fin: false)
                    frames.append(.crypto(offset: chunk.offset, length: chunk.length))
                    isAckEliciting = true
                    self.countCryptoFrame(sent: true, in: space, length: chunk.length)
                    if isRetransmission {
                        self.statistics.increment(.txRetransmittedCryptoFrames)
                        self.statistics.increment(.txRetransmittedCryptoBytes, by: chunk.length)
                    }
                }

                if space == .applicationData && (self.handshake.isComplete || isEarlyData)
                    && (!congestionLimited || mayExceedCongestionWindow)
                {
                    if self.writeApplicationFrames(
                        into: &writer,
                        limit: frameLimit,
                        frames: &frames,
                        isAckEliciting: &isAckEliciting,
                        earlyData: isEarlyData,
                        now: now
                    ) {
                        // PATH_CHALLENGE and PATH_RESPONSE need a datagram of 1200 bytes.
                        padDatagramTo = max(padDatagramTo ?? 0, Self.minimumInitialDatagramSize)
                    }
                }

                // A probe must be ack-eliciting.
                if self.probesPending[Int(space.rawValue)] > 0 {
                    if !isAckEliciting && writer.offset < frameLimit {
                        _ = writer.uint8(0x01)
                        frames.append(.ping)
                        isAckEliciting = true
                    }
                    self.probesPending[Int(space.rawValue)] &-= 1
                }
            }

            guard !frames.isEmpty else { return nil }

            // Header protection samples 16 bytes starting 4 bytes after the packet number.
            let minimumPayload = 4 &- packetNumberLength
            if writer.offset &- payloadStart < minimumPayload {
                _ = writer.zeros(minimumPayload &- (writer.offset &- payloadStart))
                hasPadding = true
            }
            if let padDatagramTo {
                let target = padDatagramTo &- offset &- Self.tagLength
                if writer.offset < target {
                    let padding = min(target, frameLimit) &- writer.offset
                    _ = writer.zeros(padding)
                    hasPadding = true
                }
            }
            payloadEnd = writer.offset
        }

        let totalLength = payloadEnd &+ Self.tagLength
        let payloadLength = totalLength &- headerLength
        if isLongHeader {
            // Fill in the length field: packet number, frames and tag.
            var lengthWriter = CoreWriter(
                buffer._mutatingExtracting((offset &+ lengthFieldOffset)..<(offset &+ lengthFieldOffset &+ 2))
            )
            _ = lengthWriter.vle2(UInt16(payloadLength))
        }

        var packet: Packet
        if isLongHeader {
            packet = Packet(
                destinationConnectionID: self.peerConnectionID,
                sourceConnectionID: self.localConnectionID,
                keyState: keyState,
                space: space,
                payloadLength: UInt16(payloadLength),
                headerLength: UInt16(headerLength),
                version: .v1
            )
        } else {
            packet = Packet(
                destinationConnectionID: destination,
                headerLength: UInt16(headerLength),
                spin: self.spinValue
            )
            try? packet.updateKeyState(to: self.keyPhase)
            packet.payloadLength = UInt16(payloadLength)
        }
        packet.number = packetNumber
        packet.packetNumberLength = UInt8(packetNumberLength)
        packet.tagLength = UInt8(Self.tagLength)
        var sealRegion = buffer._mutatingExtracting(offset..<(offset &+ totalLength))
        do {
            try self.protector.seal(&packet, buffer: &sealRegion)
        } catch {
            self.log.error("Failed to seal packet: \(error)")
            return nil
        }

        let isInFlight = isAckEliciting || hasPadding
        self.recovery.onPacketSent(
            CoreSentPacket(
                packetNumber: UInt64(packetNumber.value),
                timeSent: now,
                size: totalLength,
                isAckEliciting: isAckEliciting,
                isInFlight: isInFlight,
                frames: frames
            ),
            in: space
        )
        // The first ack-eliciting packet since a packet arrived restarts the idle timer
        // (RFC 9000 Section 10.1).
        if isAckEliciting && !self.sentAckElicitingSinceReceive {
            self.sentAckElicitingSinceReceive = true
            if let idleTimeout = self.idleTimeout {
                self.idleDeadline = now.advanced(by: idleTimeout)
            }
        }
        return totalLength
    }

    private func writePacketNumber(_ encoded: EncodedPacketNumber, into writer: inout CoreWriter) -> Bool {
        let size = encoded.size.rawValue
        let value = UInt64(bitPattern: encoded.number)
        for i in 0..<size {
            guard writer.uint8(UInt8(truncatingIfNeeded: value >> UInt64(8 * (size &- 1 &- i)))) else { return false }
        }
        return true
    }

    /// Writes the 1-RTT frames due. Returns whether PATH_CHALLENGE or PATH_RESPONSE was among
    /// them. A 0-RTT packet carries only what the application sends (RFC 9000 Section 12.4).
    private mutating func writeApplicationFrames(
        into writer: inout CoreWriter,
        limit: Int,
        frames: inout [CoreSentFrame],
        isAckEliciting: inout Bool,
        earlyData: Bool,
        now: NetworkClock.Instant
    ) -> Bool {
        #if DEBUG
        while let frame = self.injectedFrames.first, writer.offset &+ frame.count <= limit {
            _ = writer.bytes(frame.span.bytes)
            self.injectedFrames.removeFirst()
            frames.append(.ping)
            isAckEliciting = true
        }
        #endif
        if self.keepAlivePending && !earlyData && writer.offset < limit {
            _ = writer.uint8(0x01)
            self.keepAlivePending = false
            frames.append(.keepAlive)
            self.statistics.increment(.keepAliveFramesSent)
            isAckEliciting = true
        }
        if self.handshakeDonePending && !earlyData && writer.offset < limit {
            _ = writer.uint8(0x1e)
            self.handshakeDonePending = false
            frames.append(.handshakeDone)
            isAckEliciting = true
        }
        let wrotePathFrames =
            !earlyData
            && self.writePathFrames(
            for: self.activePath,
            into: &writer,
            limit: limit,
            frames: &frames,
            isAckEliciting: &isAckEliciting,
            now: now
        )
        if self.pingPending && !earlyData && writer.offset < limit {
            _ = writer.uint8(0x01)
            self.pingPending = false
            frames.append(.ping)
            isAckEliciting = true
        }
        if self.maxDataPending && writer.offset &+ 9 <= limit {
            if writer.vle(0x10) && writer.vle(self.receiveMaxData) {
                self.maxDataPending = false
                frames.append(.maxData)
                isAckEliciting = true
            }
        }
        if self.streams.maxStreamsBidirectionalPending && writer.offset &+ 9 <= limit {
            if writer.vle(0x12) && writer.vle(self.streams.localMaxStreamsBidirectional) {
                self.streams.maxStreamsBidirectionalPending = false
                self.streams.advertisedMaxStreamsBidirectional = self.streams.localMaxStreamsBidirectional
                frames.append(.maxStreamsBidirectional)
                isAckEliciting = true
            }
        }
        if self.streams.maxStreamsUnidirectionalPending && writer.offset &+ 9 <= limit {
            if writer.vle(0x13) && writer.vle(self.streams.localMaxStreamsUnidirectional) {
                self.streams.maxStreamsUnidirectionalPending = false
                self.streams.advertisedMaxStreamsUnidirectional = self.streams.localMaxStreamsUnidirectional
                frames.append(.maxStreamsUnidirectional)
                isAckEliciting = true
            }
        }

        if !earlyData {
            self.writeConnectionIDFrames(into: &writer, limit: limit, frames: &frames, isAckEliciting: &isAckEliciting)
        }
        self.writeDatagramFrames(into: &writer, limit: limit, frames: &frames, isAckEliciting: &isAckEliciting)

        // Stream frames, round robin.
        var deferred: [UInt64] = []
        while writer.offset &+ 24 < limit, let id = self.streams.popSendQueue() {
            guard var stream = self.streams.streams.removeValue(forKey: id) else { continue }
            self.writeStreamFrames(
                for: &stream,
                into: &writer,
                limit: limit,
                frames: &frames,
                isAckEliciting: &isAckEliciting
            )
            let stillPending = stream.hasPendingFrames
            let blockedOnConnection =
                stillPending && !stream.send.hasRetransmission && !stream.resetPending
                && !stream.stopSendingPending && !stream.maxStreamDataPending && self.sentData >= self.sendMaxData
                && stream.send.unsentCount > 0
            self.storeOrRemove(stream)
            if stillPending && self.streams.streams[id] != nil {
                if blockedOnConnection {
                    deferred.append(id)
                } else if writer.offset &+ 24 >= limit {
                    // The packet is full; this stream goes first next time.
                    self.streams.pushFrontSendQueue(id)
                } else {
                    deferred.append(id)
                }
            }
        }
        for id in deferred {
            self.streams.enqueueForSending(id)
        }
        return wrotePathFrames
    }

    /// Writes queued DATAGRAM frames, oldest first, as long as they fit. One that can never fit
    /// a packet, or the peer's limit, is dropped.
    private mutating func writeDatagramFrames(
        into writer: inout CoreWriter,
        limit: Int,
        frames: inout [CoreSentFrame],
        isAckEliciting: inout Bool
    ) {
        let maximumPayload = self.maxDatagramPayloadSize
        while let payload = self.datagramsToSend.first {
            guard payload.count <= maximumPayload else {
                self.log.debug("Dropping a datagram of \(payload.count) bytes; at most \(maximumPayload) fit")
                self.datagramsToSend.removeFirst()
                continue
            }
            let frameLength = 1 &+ CoreWriter.vleLength(UInt64(payload.count)) &+ payload.count
            guard writer.offset &+ frameLength <= limit else {
                if frames.isEmpty {
                    // Nothing else is in this packet, so the datagram won't fit any packet.
                    self.log.debug("Dropping a datagram of \(payload.count) bytes that doesn't fit a packet")
                    self.datagramsToSend.removeFirst()
                    continue
                }
                // The next packet has more room.
                return
            }
            guard writer.vle(0x31), writer.vle(UInt64(payload.count)), writer.bytes(payload.span.bytes) else { return }
            self.datagramsToSend.removeFirst()
            frames.append(.datagram)
            self.statistics.increment(.txDatagramFrameWithLength)
            isAckEliciting = true
        }
    }

    private mutating func writeStreamFrames(
        for stream: inout CoreStream,
        into writer: inout CoreWriter,
        limit: Int,
        frames: inout [CoreSentFrame],
        isAckEliciting: inout Bool
    ) {
        let id = stream.id
        if stream.resetPending, let code = stream.resetCode, writer.offset &+ 25 <= limit {
            // The final size is what was sent: bytes buffered past flow control never count
            // (RFC 9000 § 4.5). It stays the same for retransmissions, as nothing is sent after.
            if writer.vle(0x04) && writer.vle(id) && writer.vle(code) && writer.vle(stream.send.sendOffset) {
                stream.resetPending = false
                stream.send.reset()
                frames.append(.resetStream(id: id))
                self.statistics.increment(.txStreamResetFrames)
                isAckEliciting = true
            }
        }
        if stream.stopSendingPending, let code = stream.stopSendingCode, writer.offset &+ 17 <= limit {
            if writer.vle(0x05) && writer.vle(id) && writer.vle(code) {
                stream.stopSendingPending = false
                frames.append(.stopSending(id: id))
                self.statistics.increment(.txStreamStopSendingFrames)
                isAckEliciting = true
            }
        }
        if stream.maxStreamDataPending, writer.offset &+ 17 <= limit {
            if writer.vle(0x11) && writer.vle(id) && writer.vle(stream.receiveLimit) {
                stream.maxStreamDataPending = false
                frames.append(.maxStreamData(id: id))
                isAckEliciting = true
            }
        }
        guard stream.canSend, stream.resetCode == nil else { return }
        while true {
            // Frame header: type, stream ID, offset, two byte length.
            let overhead = 1 &+ CoreWriter.vleLength(id) &+ 8 &+ 2
            let available = limit &- writer.offset &- overhead
            guard available >= 0 else { return }
            let connectionCredit = self.sendMaxData > self.sentData ? self.sendMaxData &- self.sentData : 0
            let flowControlLimit = min(stream.sendLimit, stream.send.sendOffset &+ connectionCredit)
            guard
                let chunk = stream.send.nextChunk(
                    maximumLength: min(available, (1 << 14) &- 1),
                    flowControlLimit: flowControlLimit
                )
            else {
                return
            }
            var type: UInt64 = 0x08 | 0x02
            if chunk.offset > 0 { type |= 0x04 }
            if chunk.fin { type |= 0x01 }
            var ok = writer.vle(type) && writer.vle(id)
            if chunk.offset > 0 {
                ok = ok && writer.vle(chunk.offset)
            }
            ok = ok && writer.vle2(UInt16(chunk.length))
            ok = ok && stream.send.copy(offset: chunk.offset, length: chunk.length, into: &writer)
            guard ok else { return }
            let previousSendOffset = stream.send.sendOffset
            stream.send.markSent(offset: chunk.offset, length: chunk.length, fin: chunk.fin)
            let newBytes = stream.send.sendOffset &- previousSendOffset
            self.sentData &+= newBytes
            frames.append(.stream(id: id, offset: chunk.offset, length: chunk.length, fin: chunk.fin))
            isAckEliciting = true
            self.statistics.increment(.txStreamFrames)
            self.statistics.increment(.txStreamBytes, by: chunk.length)
            if UInt64(chunk.length) > newBytes {
                self.statistics.increment(.txRetransmittedBytes, by: chunk.length &- Int(newBytes))
            }
            if chunk.length == 0 { return }
        }
    }

    // MARK: Closing

    private mutating func sendClose(into buffer: inout MutableSpan<UInt8>, now: NetworkClock.Instant) -> Int? {
        guard let close = self.pendingClose else { return nil }
        if !self.closeFrameSentInState {
            self.closeFrameSentInState = true
            self.closeSpacesToSend = self.closeSpaces()
        }
        // One datagram per space: some receivers drop the rest of a datagram after a packet they
        // can't decrypt, which a coalesced close in a space the peer already dropped would be.
        let limit = min(buffer.count, self.configuration.maxDatagramSize)
        while let space = self.closeSpacesToSend.first {
            self.closeSpacesToSend.removeFirst()
            if let length = self.writeClosePacket(close, in: space, into: &buffer, at: 0, maximumLength: limit) {
                return length
            }
        }
        return nil
    }

    /// The spaces a CONNECTION_CLOSE goes out in. Before the handshake is confirmed the peer may
    /// lack the keys of the newest space, so it is every space we have keys for (RFC 9000
    /// Section 10.2.3).
    private func closeSpaces() -> [PacketNumberSpace] {
        var spaces: [PacketNumberSpace] = []
        if !self.spaceDiscarded[0] && self.protector.sealKeyReady(for: .initial) {
            spaces.append(.initial)
        }
        if !self.spaceDiscarded[1] && self.protector.sealKeyReady(for: .handshake) {
            spaces.append(.handshake)
        }
        if self.protector.sealKeyReady(for: self.keyPhase) && self.handshake.isComplete {
            if self.isHandshakeConfirmed {
                spaces = [.applicationData]
            } else {
                spaces.append(.applicationData)
            }
        }
        return spaces
    }

    /// Writes one packet of `space` carrying CONNECTION_CLOSE at `offset`. Returns its length.
    private mutating func writeClosePacket(
        _ close: PendingClose,
        in space: PacketNumberSpace,
        into buffer: inout MutableSpan<UInt8>,
        at offset: Int,
        maximumLength: Int
    ) -> Int? {
        let keyState: PacketKeyState = space == .initial ? .initial : (space == .handshake ? .handshake : self.keyPhase)
        guard self.protector.sealKeyReady(for: keyState), maximumLength > 64 else { return nil }
        let packetNumber = self.protector.getPacketNumber(for: space)
        guard let encoded = try? packetNumber.encode(lastAcked: .none, fixedSize: .fourBytes) else { return nil }
        let isLongHeader = space != .applicationData
        // An application close is sent as a transport close with APPLICATION_ERROR outside 1-RTT
        // packets, which hides the application's code and reason (RFC 9000 Section 10.2.3).
        let isApplication = close.isApplication && space == .applicationData
        let hidesApplicationClose = close.isApplication && !isApplication
        let errorCode = hidesApplicationClose ? CoreTransportError.applicationError : close.errorCode
        var headerLength = 0
        var lengthFieldOffset = 0
        var payloadEnd = 0
        do {
            var writer = CoreWriter(buffer._mutatingExtracting(offset..<(offset &+ maximumLength)))
            if isLongHeader {
                let type: UInt8 = space == .initial ? 0x00 : 0x02
                var ok = writer.uint8(0xc0 | (type << 4) | encoded.headerFieldSize)
                ok = ok && writer.uint32(self.version)
                ok = ok && writer.uint8(UInt8(self.peerConnectionID.length))
                ok =
                    ok
                    && writer.bytes(
                        self.peerConnectionID.connectionIDStorage.span.bytes.extracting(
                            0..<self.peerConnectionID.length
                        )
                    )
                ok = ok && writer.uint8(UInt8(self.localConnectionID.length))
                ok =
                    ok
                    && writer.bytes(
                        self.localConnectionID.connectionIDStorage.span.bytes.extracting(
                            0..<self.localConnectionID.length
                        )
                    )
                if space == .initial {
                    ok = ok && writer.vle(0)
                }
                lengthFieldOffset = writer.offset
                ok = ok && writer.vle2(0)
                guard ok else { return nil }
            } else {
                guard writer.uint8(0x40 | self.keyPhaseBit | encoded.headerFieldSize),
                    writer.bytes(
                        self.peerConnectionID.connectionIDStorage.span.bytes.extracting(
                            0..<self.peerConnectionID.length
                        )
                    )
                else {
                    return nil
                }
            }
            headerLength = writer.offset
            guard self.writePacketNumber(encoded, into: &writer) else { return nil }
            let reasonBytes = hidesApplicationClose ? [] : Array(close.reason.utf8.prefix(256))
            var ok = writer.vle(isApplication ? 0x1d : 0x1c) && writer.vle(errorCode)
            if !isApplication {
                ok = ok && writer.vle(close.frameType)
            }
            ok = ok && writer.vle(UInt64(reasonBytes.count)) && writer.bytes(reasonBytes.span.bytes)
            guard ok, writer.remaining >= Self.tagLength else { return nil }
            payloadEnd = writer.offset
        }
        let totalLength = payloadEnd &+ Self.tagLength
        let payloadLength = totalLength &- headerLength
        if isLongHeader {
            var lengthWriter = CoreWriter(
                buffer._mutatingExtracting((offset &+ lengthFieldOffset)..<(offset &+ lengthFieldOffset &+ 2))
            )
            _ = lengthWriter.vle2(UInt16(payloadLength))
        }
        var packet: Packet
        if isLongHeader {
            packet = Packet(
                destinationConnectionID: self.peerConnectionID,
                sourceConnectionID: self.localConnectionID,
                keyState: keyState,
                space: space,
                payloadLength: UInt16(payloadLength),
                headerLength: UInt16(headerLength),
                version: .v1
            )
        } else {
            packet = Packet(
                destinationConnectionID: self.peerConnectionID,
                headerLength: UInt16(headerLength),
                spin: self.spinValue
            )
            try? packet.updateKeyState(to: self.keyPhase)
            packet.payloadLength = UInt16(payloadLength)
        }
        packet.number = packetNumber
        packet.packetNumberLength = UInt8(encoded.size.rawValue)
        packet.tagLength = UInt8(Self.tagLength)
        var sealRegion = buffer._mutatingExtracting(offset..<(offset &+ totalLength))
        do {
            try self.protector.seal(&packet, buffer: &sealRegion)
        } catch {
            return nil
        }
        return totalLength
    }
}

#endif
