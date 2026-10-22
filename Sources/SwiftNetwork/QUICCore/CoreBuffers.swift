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

/// The outbound bytes of a stream or a crypto level.
///
/// Bytes stay buffered until the peer acknowledges them. Lost ranges are queued for
/// retransmission and sent before new data.
@available(Network 0.1.0, *)
struct CoreSendBuffer {
    /// Unacknowledged bytes, starting at `baseOffset + storageStart` in the stream.
    private var storage: [UInt8] = []
    private var storageStart = 0
    /// The stream offset of `storage[0]`.
    private var baseOffset: UInt64 = 0

    /// The offset of the next byte that was never sent.
    private(set) var sendOffset: UInt64 = 0
    /// Ranges that were lost and have to be sent again.
    private var retransmit = CoreRangeSet()
    /// Acknowledged ranges above the buffer start.
    private var acked = CoreRangeSet()

    /// The final size, once the application finished the stream.
    private(set) var finalSize: UInt64?
    private(set) var finSent = false
    private var finNeedsRetransmit = false
    private(set) var finAcked = false

    /// The offset after the last enqueued byte.
    var writeOffset: UInt64 {
        self.baseOffset &+ UInt64(self.storage.count)
    }

    /// The number of enqueued bytes that were never sent.
    var unsentCount: UInt64 {
        self.writeOffset &- self.sendOffset
    }

    /// The number of bytes buffered, including sent but unacknowledged ones.
    var bufferedCount: Int {
        self.storage.count &- self.storageStart
    }

    var isFinished: Bool { self.finalSize != nil }

    /// Whether every byte and the FIN were acknowledged.
    var isFullyAcknowledged: Bool {
        guard let finalSize else { return false }
        return self.finAcked && self.baseOffset &+ UInt64(self.storageStart) >= finalSize
    }

    /// Whether there are bytes or a FIN to send, ignoring flow control.
    var hasDataToSend: Bool {
        !self.retransmit.isEmpty || self.unsentCount > 0 || self.finNeedsRetransmit
            || (self.finalSize != nil && !self.finSent)
    }

    /// Whether there are lost bytes or a lost FIN to resend.
    var hasRetransmission: Bool {
        !self.retransmit.isEmpty || self.finNeedsRetransmit
    }

    mutating func append(_ bytes: RawSpan) {
        precondition(self.finalSize == nil, "Appending to a finished stream")
        bytes.withUnsafeBytes { self.storage.append(contentsOf: $0) }
    }

    mutating func append(_ bytes: [UInt8]) {
        precondition(self.finalSize == nil, "Appending to a finished stream")
        self.storage.append(contentsOf: bytes)
    }

    mutating func finish() {
        if self.finalSize == nil {
            self.finalSize = self.writeOffset
        }
    }

    /// The next range to send, at most `maximumLength` bytes, preferring retransmissions. New data
    /// is limited to offsets below `flowControlLimit`.
    ///
    /// Returns `nil` if there is nothing to send. A FIN-only chunk has length zero.
    func nextChunk(maximumLength: Int, flowControlLimit: UInt64) -> (offset: UInt64, length: Int, fin: Bool)? {
        if let lost = self.retransmit.ranges.first {
            let length = Int(min(UInt64(maximumLength), lost.upperBound &- lost.lowerBound))
            guard length > 0 else { return nil }
            let end = lost.lowerBound &+ UInt64(length)
            let fin = self.finalSize == end && (self.finNeedsRetransmit || !self.finSent)
            return (lost.lowerBound, length, fin)
        }
        if self.finNeedsRetransmit, let finalSize, self.unsentCount == 0 {
            return (finalSize, 0, true)
        }
        let available = min(self.writeOffset, max(flowControlLimit, self.sendOffset)) &- self.sendOffset
        let length = Int(min(UInt64(maximumLength), available))
        let end = self.sendOffset &+ UInt64(length)
        let fin = self.finalSize == end && !self.finSent
        guard length > 0 || fin else { return nil }
        return (self.sendOffset, length, fin)
    }

    /// Records that `length` bytes at `offset` (and the FIN, if `fin`) were written into a packet.
    mutating func markSent(offset: UInt64, length: Int, fin: Bool) {
        let end = offset &+ UInt64(length)
        if let lost = self.retransmit.ranges.first, lost.lowerBound == offset, length > 0 {
            self.retransmit.removeAll(below: end)
        }
        if end > self.sendOffset {
            self.sendOffset = end
        }
        if fin {
            self.finSent = true
            self.finNeedsRetransmit = false
        }
    }

    /// Copies `length` bytes starting at stream offset `offset` into `writer`.
    func copy(offset: UInt64, length: Int, into writer: inout CoreWriter) -> Bool {
        guard writer.remaining >= length else { return false }
        let start = Int(offset &- self.baseOffset)
        precondition(start >= self.storageStart && start &+ length <= self.storage.count)
        return self.storage.span.bytes.withUnsafeBytes { buffer in
            writer.bytes(RawSpan(_unsafeBytes: UnsafeRawBufferPointer(rebasing: buffer[start..<(start &+ length)])))
        }
    }

    mutating func onAcked(offset: UInt64, length: Int, fin: Bool) {
        if fin {
            self.finAcked = true
            self.finNeedsRetransmit = false
        }
        guard length > 0 else { return }
        let range = offset..<(offset &+ UInt64(length))
        self.acked.insert(range)
        // Release the acknowledged prefix.
        let start = self.baseOffset &+ UInt64(self.storageStart)
        if let first = self.acked.ranges.first, first.lowerBound <= start, first.upperBound > start {
            let releasable = Int(first.upperBound &- start)
            self.storageStart &+= releasable
            self.acked.removeAll(below: first.upperBound)
            self.retransmit.removeAll(below: first.upperBound)
            self.compactIfNeeded()
        }
    }

    mutating func onLost(offset: UInt64, length: Int, fin: Bool) {
        let start = self.baseOffset &+ UInt64(self.storageStart)
        if length > 0 {
            let lower = max(offset, start)
            let upper = offset &+ UInt64(length)
            if lower < upper {
                // Only resend what is not acknowledged yet.
                var cursor = lower
                for ackedRange in self.acked.ranges where ackedRange.upperBound > cursor {
                    if ackedRange.lowerBound >= upper { break }
                    if ackedRange.lowerBound > cursor {
                        self.retransmit.insert(cursor..<ackedRange.lowerBound)
                    }
                    cursor = max(cursor, ackedRange.upperBound)
                }
                if cursor < upper {
                    self.retransmit.insert(cursor..<upper)
                }
            }
        }
        if fin && !self.finAcked {
            self.finNeedsRetransmit = true
        }
    }

    /// Drops all buffered data, for a reset stream.
    mutating func reset() {
        self.baseOffset = self.writeOffset
        self.storage.removeAll()
        self.storageStart = 0
        self.retransmit.removeAll()
        self.acked.removeAll()
        self.finNeedsRetransmit = false
    }

    private mutating func compactIfNeeded() {
        if self.storageStart == self.storage.count {
            self.baseOffset &+= UInt64(self.storageStart)
            self.storage.removeAll(keepingCapacity: true)
            self.storageStart = 0
        } else if self.storageStart > 4096 && self.storageStart > self.storage.count / 2 {
            self.baseOffset &+= UInt64(self.storageStart)
            self.storage.removeFirst(self.storageStart)
            self.storageStart = 0
        }
    }
}

/// The inbound bytes of a stream or a crypto level, reassembled in order.
@available(Network 0.1.0, *)
struct CoreReceiveBuffer {
    /// In-order bytes not yet consumed, starting at `readOffset`.
    private var contiguous: [UInt8] = []
    private var contiguousStart = 0
    /// The offset of the next byte the application reads.
    private(set) var readOffset: UInt64 = 0
    /// Out-of-order segments above the contiguous end, sorted by offset.
    private var segments: [(offset: UInt64, bytes: [UInt8])] = []
    /// The highest offset received so far.
    private(set) var highestOffset: UInt64 = 0
    private(set) var finalSize: UInt64?
    /// Whether the application read up to the final size, or dropped the bytes.
    private var finDelivered = false

    /// The offset after the last in-order byte.
    var contiguousEnd: UInt64 {
        self.readOffset &+ UInt64(self.contiguous.count &- self.contiguousStart)
    }

    var readableCount: Int {
        self.contiguous.count &- self.contiguousStart
    }

    /// Whether the application read every byte up to the final size, and with it the FIN.
    ///
    /// Arriving at the final size isn't enough: a stream without data still owes its reader one
    /// read, or the FIN would be lost when the stream goes away.
    var isFinishedReading: Bool {
        self.finDelivered
    }

    /// Whether every byte up to the final size arrived.
    var isComplete: Bool {
        guard let finalSize else { return false }
        return self.contiguousEnd >= finalSize
    }

    var bufferedOutOfOrderCount: Int {
        self.segments.reduce(0) { $0 &+ $1.bytes.count }
    }

    enum InsertError: Error {
        case finalSizeViolation
    }

    /// Adds `bytes` at `offset`. Returns the number of bytes that became readable.
    @discardableResult
    mutating func insert(offset: UInt64, bytes: RawSpan, fin: Bool) throws(InsertError) -> Int {
        let length = UInt64(bytes.byteCount)
        let end = offset &+ length
        if let finalSize {
            if end > finalSize || (fin && end != finalSize) {
                throw .finalSizeViolation
            }
        } else if fin {
            if end < self.highestOffset {
                throw .finalSizeViolation
            }
            self.finalSize = end
        }
        if end > self.highestOffset {
            self.highestOffset = end
        }
        let contiguousEnd = self.contiguousEnd
        guard end > contiguousEnd else { return 0 }
        let before = self.readableCount
        if offset <= contiguousEnd {
            let skip = Int(contiguousEnd &- offset)
            bytes.withUnsafeBytes { buffer in
                self.contiguous.append(contentsOf: UnsafeRawBufferPointer(rebasing: buffer[skip...]))
            }
            self.drainSegments()
        } else {
            self.insertSegment(offset: offset, bytes: [UInt8](copying: bytes))
        }
        return self.readableCount &- before
    }

    /// Calls `body` with the readable bytes; `body` returns how many it consumed.
    mutating func read<Result>(_ body: (RawSpan) -> (consumed: Int, result: Result)) -> Result {
        let start = self.contiguousStart
        let end = self.contiguous.count
        let (consumed, result) = self.contiguous.span.bytes.withUnsafeBytes { buffer in
            body(RawSpan(_unsafeBytes: UnsafeRawBufferPointer(rebasing: buffer[start..<end])))
        }
        precondition(consumed >= 0 && consumed <= end &- start)
        self.consume(consumed)
        if let finalSize = self.finalSize, self.readOffset >= finalSize {
            self.finDelivered = true
        }
        return result
    }

    mutating func consume(_ count: Int) {
        self.contiguousStart &+= count
        self.readOffset &+= UInt64(count)
        if self.contiguousStart == self.contiguous.count {
            self.contiguous.removeAll(keepingCapacity: true)
            self.contiguousStart = 0
        } else if self.contiguousStart > 4096 && self.contiguousStart > self.contiguous.count / 2 {
            self.contiguous.removeFirst(self.contiguousStart)
            self.contiguousStart = 0
        }
    }

    /// Drops everything buffered, and returns how many unread bytes were dropped.
    mutating func discard() -> UInt64 {
        let dropped = self.highestOffset &- self.readOffset
        self.contiguous.removeAll()
        self.contiguousStart = 0
        self.segments.removeAll()
        self.readOffset = self.highestOffset
        if let finalSize = self.finalSize, self.readOffset >= finalSize {
            self.finDelivered = true
        }
        return dropped
    }

    /// Records the final size from a RESET_STREAM.
    mutating func reset(finalSize: UInt64) throws(InsertError) {
        if let existing = self.finalSize, existing != finalSize {
            throw .finalSizeViolation
        }
        if finalSize < self.highestOffset {
            throw .finalSizeViolation
        }
        self.finalSize = finalSize
        self.highestOffset = finalSize
    }

    private mutating func insertSegment(offset: UInt64, bytes: [UInt8]) {
        var index = self.segments.count
        while index > 0 && self.segments[index &- 1].offset > offset {
            index &-= 1
        }
        self.segments.insert((offset, bytes), at: index)
    }

    private mutating func drainSegments() {
        while let first = self.segments.first {
            let contiguousEnd = self.contiguousEnd
            guard first.offset <= contiguousEnd else { break }
            self.segments.removeFirst()
            let end = first.offset &+ UInt64(first.bytes.count)
            if end > contiguousEnd {
                let skip = Int(contiguousEnd &- first.offset)
                self.contiguous.append(contentsOf: first.bytes[skip...])
            }
        }
    }
}

#endif
