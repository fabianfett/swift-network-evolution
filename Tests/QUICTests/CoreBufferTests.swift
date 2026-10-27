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

/// The stream and crypto buffers of `QUICConnectionCore`: reassembly of what arrives (RFC 9000
/// Section 2.2) and retransmission of what was lost (Section 13.3).
@available(Network 0.1.0, *)
final class CoreBufferTests: XCTestCase {
    private struct Chunk: Equatable {
        var offset: UInt64
        var length: Int
        var fin: Bool
    }

    @discardableResult
    private static func insert(
        _ buffer: inout CoreReceiveBuffer,
        at offset: UInt64,
        _ bytes: [UInt8],
        fin: Bool = false
    ) throws(CoreReceiveBuffer.InsertError) -> Int {
        try buffer.insert(offset: offset, bytes: bytes.span.bytes, fin: fin)
    }

    private static func readAll(_ buffer: inout CoreReceiveBuffer) -> [UInt8] {
        buffer.read { bytes in (bytes.byteCount, [UInt8](copying: bytes)) }
    }

    private static func nextChunk(
        _ buffer: CoreSendBuffer,
        maximumLength: Int = 1000,
        flowControlLimit: UInt64 = .max
    ) -> Chunk? {
        buffer.nextChunk(maximumLength: maximumLength, flowControlLimit: flowControlLimit).map {
            Chunk(offset: $0.offset, length: $0.length, fin: $0.fin)
        }
    }

    /// Sends the next chunk and returns it.
    private static func send(_ buffer: inout CoreSendBuffer, maximumLength: Int = 1000) -> Chunk? {
        guard let chunk = Self.nextChunk(buffer, maximumLength: maximumLength) else { return nil }
        buffer.markSent(offset: chunk.offset, length: chunk.length, fin: chunk.fin)
        return chunk
    }

    // MARK: Receiving

    func testOutOfOrderDataBecomesReadableOnceTheGapIsFilled() throws {
        var buffer = CoreReceiveBuffer()
        XCTAssertEqual(try Self.insert(&buffer, at: 6, [6, 7, 8]), 0)
        XCTAssertEqual(try Self.insert(&buffer, at: 3, [3, 4, 5]), 0)
        XCTAssertEqual(buffer.readableCount, 0)
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 6)
        XCTAssertEqual(try Self.insert(&buffer, at: 0, [0, 1, 2]), 9)
        XCTAssertEqual(Self.readAll(&buffer), Array(0...8))
        XCTAssertEqual(buffer.readOffset, 9)
    }

    /// Overlapping and repeated data is delivered once; the bytes at an offset don't change
    /// (RFC 9000 Section 2.2).
    func testOverlappingAndRepeatedDataIsDeliveredOnce() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 4, [4, 5, 6, 7])
        // Overlaps the start of the segment above.
        try Self.insert(&buffer, at: 2, [2, 3, 4, 5])
        // Covered completely by what is buffered.
        try Self.insert(&buffer, at: 5, [5, 6])
        // Overlaps the end.
        try Self.insert(&buffer, at: 6, [6, 7, 8, 9])
        XCTAssertEqual(try Self.insert(&buffer, at: 0, [0, 1, 2]), 10)
        XCTAssertEqual(Self.readAll(&buffer), Array(0...9))
        // Already read.
        XCTAssertEqual(try Self.insert(&buffer, at: 0, [0, 1, 2, 3]), 0)
        // Partly read.
        XCTAssertEqual(try Self.insert(&buffer, at: 8, [8, 9, 10, 11]), 2)
        XCTAssertEqual(Self.readAll(&buffer), [10, 11])
    }

    /// RFC 9000 Section 4.5: the final size can't change, and no data lies beyond it.
    func testDataBeyondOrDisagreeingWithTheFinalSizeIsRejected() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 0, [0, 1, 2, 3], fin: true)
        XCTAssertEqual(buffer.finalSize, 4)
        XCTAssertThrowsError(try Self.insert(&buffer, at: 3, [3, 4]))
        XCTAssertThrowsError(try Self.insert(&buffer, at: 0, [0, 1], fin: true))
        // Repeating it is fine.
        XCTAssertNoThrow(try Self.insert(&buffer, at: 2, [2, 3], fin: true))

        var other = CoreReceiveBuffer()
        try Self.insert(&other, at: 0, [0, 1, 2, 3])
        // A final size below data already received.
        XCTAssertThrowsError(try Self.insert(&other, at: 0, [0, 1], fin: true))
        XCTAssertThrowsError(try other.reset(finalSize: 2))
        XCTAssertNoThrow(try other.reset(finalSize: 6))
        XCTAssertThrowsError(try other.reset(finalSize: 7))
    }

    func testTheFinIsDeliveredWithTheLastByte() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 2, [2, 3], fin: true)
        XCTAssertFalse(buffer.isComplete)
        try Self.insert(&buffer, at: 0, [0, 1])
        XCTAssertTrue(buffer.isComplete)
        XCTAssertFalse(buffer.isFinishedReading)
        XCTAssertEqual(Self.readAll(&buffer), [0, 1, 2, 3])
        XCTAssertTrue(buffer.isFinishedReading)
    }

    /// A frame without data stores nothing, wherever it lies: else a peer could make the buffer
    /// hold any number of empty segments.
    func testEmptyInsertsStoreNothing() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 0, [0, 1])
        for offset in stride(from: UInt64(3), to: 100_000, by: 7) {
            XCTAssertEqual(try Self.insert(&buffer, at: offset, []), 0)
        }
        XCTAssertEqual(buffer.bufferedSegmentCount, 0)
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 0)
        XCTAssertEqual(Self.readAll(&buffer), [0, 1])
    }

    /// A FIN without data still sets the final size, and completes the buffer once the bytes
    /// before it arrive.
    func testAFinWithoutDataSetsTheFinalSize() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 4, [], fin: true)
        XCTAssertEqual(buffer.finalSize, 4)
        XCTAssertEqual(buffer.bufferedSegmentCount, 0)
        XCTAssertFalse(buffer.isComplete)
        try Self.insert(&buffer, at: 2, [2, 3])
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 2)
        try Self.insert(&buffer, at: 0, [0, 1])
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 0)
        XCTAssertTrue(buffer.isComplete)
        XCTAssertEqual(Self.readAll(&buffer), [0, 1, 2, 3])
        XCTAssertTrue(buffer.isFinishedReading)

        // At the end of what arrived.
        var other = CoreReceiveBuffer()
        try Self.insert(&other, at: 0, [0, 1])
        try Self.insert(&other, at: 2, [], fin: true)
        XCTAssertTrue(other.isComplete)
        XCTAssertEqual(Self.readAll(&other), [0, 1])
        XCTAssertTrue(other.isFinishedReading)
    }

    /// A byte is buffered once, however often it arrives: else a peer could make the buffer grow
    /// without bound by sending the same range again and again.
    func testRepeatedRangesAreBufferedOnce() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 0, [0, 1])
        let range = Array(UInt8(10)..<20)
        for _ in 0..<1000 {
            XCTAssertEqual(try Self.insert(&buffer, at: 10, range), 0)
        }
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 10)
        XCTAssertEqual(buffer.bufferedSegmentCount, 1)
        // A range overlapping the start of the buffered one adds what lies before it.
        for _ in 0..<1000 {
            XCTAssertEqual(try Self.insert(&buffer, at: 5, Array(5..<15)), 0)
        }
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 15)
        XCTAssertEqual(try Self.insert(&buffer, at: 2, [2, 3, 4]), 18)
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 0)
        XCTAssertEqual(buffer.bufferedSegmentCount, 0)
        XCTAssertEqual(Self.readAll(&buffer), Array(0..<20))
    }

    /// A range spanning several segments fills the gaps between them, and each byte is read once.
    func testARangeSpanningSegmentsFillsTheGaps() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 4, [4, 5, 6])
        try Self.insert(&buffer, at: 10, [10, 11, 12])
        try Self.insert(&buffer, at: 16, [16, 17, 18])
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 9)
        try Self.insert(&buffer, at: 2, Array(2..<22))
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 20)
        XCTAssertEqual(try Self.insert(&buffer, at: 0, [0, 1]), 22)
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 0)
        XCTAssertEqual(Self.readAll(&buffer), Array(0..<22))
    }

    /// Data following on what arrived after a gap extends one segment.
    func testDataAfterAGapExtendsOneSegment() throws {
        var buffer = CoreReceiveBuffer()
        for offset in stride(from: UInt64(10), to: 1010, by: 10) {
            try Self.insert(&buffer, at: offset, [UInt8](repeating: UInt8(offset / 10), count: 10))
        }
        XCTAssertEqual(buffer.bufferedSegmentCount, 1)
        XCTAssertEqual(buffer.bufferedOutOfOrderCount, 1000)
        XCTAssertEqual(try Self.insert(&buffer, at: 0, [UInt8](repeating: 0, count: 10)), 1010)
        XCTAssertEqual(Self.readAll(&buffer), (0..<1010).map { UInt8($0 / 10) })
    }

    /// Random inserts and reads against a model that keeps a flag per byte.
    func testRandomInsertsMatchAModel() throws {
        struct SplitMix64: RandomNumberGenerator {
            var state: UInt64
            mutating func next() -> UInt64 {
                self.state &+= 0x9e37_79b9_7f4a_7c15
                var z = self.state
                z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
                z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
                return z ^ (z >> 31)
            }
        }
        let size = 4000
        let value = { (offset: Int) in UInt8(truncatingIfNeeded: offset &* 7 &+ offset / 256) }
        for seed: UInt64 in [1, 2, 3, 42, 1234] {
            var random = SplitMix64(state: seed)
            var buffer = CoreReceiveBuffer()
            var received = [Bool](repeating: false, count: size)
            var read: [UInt8] = []
            var modelContiguousEnd = 0
            for step in 0..<3000 {
                let start = Int.random(in: 0..<size, using: &random)
                let length = min(Int.random(in: 0...80, using: &random), size - start)
                let bytes = (start..<(start + length)).map(value)
                let readable = try Self.insert(&buffer, at: UInt64(start), bytes)
                for offset in start..<(start + length) { received[offset] = true }
                let before = modelContiguousEnd
                while modelContiguousEnd < size && received[modelContiguousEnd] { modelContiguousEnd += 1 }
                let outOfOrder = received[modelContiguousEnd...].filter { $0 }.count
                guard
                    readable == modelContiguousEnd - before,
                    buffer.contiguousEnd == UInt64(modelContiguousEnd),
                    buffer.bufferedOutOfOrderCount == outOfOrder
                else {
                    XCTFail(
                        """
                        seed \(seed), step \(step): readable \(readable), contiguous end \(buffer.contiguousEnd), \
                        buffered \(buffer.bufferedOutOfOrderCount); expected \(modelContiguousEnd - before), \
                        \(modelContiguousEnd), \(outOfOrder)
                        """
                    )
                    break
                }
                if Int.random(in: 0..<4, using: &random) == 0 {
                    // Read part of what is readable.
                    let count = Int.random(in: 0...buffer.readableCount, using: &random)
                    read += buffer.read { bytes in
                        (count, [UInt8](copying: bytes.extracting(0..<count)))
                    }
                }
            }
            try Self.insert(&buffer, at: 0, (0..<size).map(value))
            read += Self.readAll(&buffer)
            XCTAssertEqual(read, (0..<size).map(value), "seed \(seed)")
            XCTAssertEqual(buffer.bufferedSegmentCount, 0, "seed \(seed)")
        }
    }

    func testDiscardingCountsTheUnreadBytes() throws {
        var buffer = CoreReceiveBuffer()
        try Self.insert(&buffer, at: 0, [0, 1, 2])
        try Self.insert(&buffer, at: 6, [6, 7])
        buffer.consume(1)
        // Two unread in order, the gap, and two out of order.
        XCTAssertEqual(buffer.discard(), 7)
        XCTAssertEqual(buffer.readOffset, 8)
        XCTAssertEqual(buffer.readableCount, 0)
    }

    // MARK: Sending

    /// RFC 9000 Section 13.3: lost data goes out again before new data, apart from what was
    /// acknowledged meanwhile.
    func testLostDataIsSentAgainFirstWithoutWhatWasAcknowledged() {
        var buffer = CoreSendBuffer()
        buffer.append([UInt8](repeating: 1, count: 300))
        XCTAssertEqual(Self.send(&buffer, maximumLength: 100), Chunk(offset: 0, length: 100, fin: false))
        XCTAssertEqual(Self.send(&buffer, maximumLength: 100), Chunk(offset: 100, length: 100, fin: false))
        // A later packet acknowledged the middle of the first one.
        buffer.onAcked(offset: 40, length: 20, fin: false)
        buffer.onLost(offset: 0, length: 100, fin: false)
        XCTAssertTrue(buffer.hasRetransmission)
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 0, length: 40, fin: false))
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 60, length: 40, fin: false))
        XCTAssertFalse(buffer.hasRetransmission)
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 200, length: 100, fin: false))
        XCTAssertNil(Self.send(&buffer))
    }

    /// Acknowledged bytes are released only from the front; a gap keeps what follows it.
    func testAcknowledgedBytesAreReleasedInOrder() {
        var buffer = CoreSendBuffer()
        buffer.append([UInt8](repeating: 1, count: 300))
        buffer.finish()
        while Self.send(&buffer, maximumLength: 100) != nil {}
        buffer.onAcked(offset: 100, length: 100, fin: false)
        XCTAssertEqual(buffer.bufferedCount, 300)
        buffer.onAcked(offset: 0, length: 100, fin: false)
        XCTAssertEqual(buffer.bufferedCount, 100)
        buffer.onAcked(offset: 200, length: 100, fin: false)
        XCTAssertEqual(buffer.bufferedCount, 0)
        XCTAssertFalse(buffer.isFullyAcknowledged, "The FIN is not acknowledged yet")
        buffer.onAcked(offset: 300, length: 0, fin: true)
        XCTAssertTrue(buffer.isFullyAcknowledged)
    }

    /// A lost FIN without data goes out again on its own.
    func testALostFinIsSentAgainAlone() {
        var buffer = CoreSendBuffer()
        buffer.append([1, 2, 3])
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 0, length: 3, fin: false))
        buffer.finish()
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 3, length: 0, fin: true))
        buffer.onAcked(offset: 0, length: 3, fin: false)
        buffer.onLost(offset: 3, length: 0, fin: true)
        XCTAssertEqual(Self.send(&buffer), Chunk(offset: 3, length: 0, fin: true))
        XCTAssertNil(Self.send(&buffer))
    }

    /// Flow control limits new data, not data sent before (RFC 9000 Section 4.1).
    func testFlowControlLimitsOnlyNewData() {
        var buffer = CoreSendBuffer()
        buffer.append([UInt8](repeating: 1, count: 300))
        XCTAssertEqual(
            Self.nextChunk(buffer, flowControlLimit: 120),
            Chunk(offset: 0, length: 120, fin: false)
        )
        buffer.markSent(offset: 0, length: 120, fin: false)
        XCTAssertNil(Self.nextChunk(buffer, flowControlLimit: 120))
        buffer.onLost(offset: 0, length: 120, fin: false)
        XCTAssertEqual(
            Self.nextChunk(buffer, flowControlLimit: 120),
            Chunk(offset: 0, length: 120, fin: false)
        )
    }
}

#endif
