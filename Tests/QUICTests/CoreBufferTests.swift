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
