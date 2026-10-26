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

/// The received packet numbers of `QUICConnectionCore` and the ACK frames it builds from them
/// (RFC 9000 Sections 13.2 and 19.3).
@available(Network 0.1.0, *)
final class CoreAckTrackerTests: XCTestCase {
    private let now = NetworkClock.Instant(milliseconds: 1_000)
    private let maxAckDelay = NetworkDuration.milliseconds(25)

    /// An ACK frame as its fields, ranges descending.
    private struct DecodedAck: Equatable {
        var largest: UInt64
        var delay: UInt64
        var ranges: [ClosedRange<UInt64>]
    }

    private static func decode(_ bytes: [UInt8]) -> DecodedAck? {
        var reader = CoreReader(bytes.span.bytes)
        guard let type = reader.vle(), type == 0x02, let largest = reader.vle(), let delay = reader.vle(),
            let count = reader.vle(), let first = reader.vle()
        else {
            return nil
        }
        var ranges = [(largest - first)...largest]
        var smallest = largest - first
        for _ in 0..<count {
            guard let gap = reader.vle(), let length = reader.vle() else { return nil }
            let upper = smallest - gap - 2
            ranges.append((upper - length)...upper)
            smallest = upper - length
        }
        return DecodedAck(largest: largest, delay: delay, ranges: ranges)
    }

    private static func writeAck(
        _ tracker: CoreAckTracker,
        now: NetworkClock.Instant,
        ackDelayExponent: Int = 3
    ) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: 1500)
        let length: Int
        do {
            var writer = CoreWriter(buffer.mutableSpan)
            guard tracker.writeAck(into: &writer, now: now, ackDelayExponent: ackDelayExponent) != nil else {
                return []
            }
            length = writer.offset
        }
        XCTAssertLessThanOrEqual(length, tracker.ackFrameLength(now: now, ackDelayExponent: ackDelayExponent))
        return Array(buffer[0..<length])
    }

    private func receive(
        _ tracker: inout CoreAckTracker,
        _ packetNumbers: [UInt64],
        isAckEliciting: Bool = true
    ) {
        for packetNumber in packetNumbers {
            tracker.onPacketReceived(
                packetNumber,
                isAckEliciting: isAckEliciting,
                immediate: false,
                maxAckDelay: self.maxAckDelay,
                now: self.now
            )
        }
    }

    // MARK: Ranges

    func testRangesCoalesceInAnyOrder() {
        var set = CoreRangeSet()
        for value: UInt64 in [5, 3, 4, 1, 0, 2] {
            set.insert(value)
        }
        set.insert(10..<12)
        set.insert(8)
        XCTAssertEqual(set.ranges, [0..<6, 8..<9, 10..<12])
        // A duplicate or a covered range changes nothing.
        set.insert(4)
        set.insert(1..<5)
        XCTAssertEqual(set.ranges, [0..<6, 8..<9, 10..<12])
        // One range spanning several merges them.
        set.insert(5..<11)
        XCTAssertEqual(set.ranges, [0..<12])
        XCTAssertTrue(set.contains(11))
        XCTAssertFalse(set.contains(12))
        XCTAssertTrue(set.contains(2..<9))
    }

    func testRemovingBelowAValueAndTrimmingDropTheLowestRanges() {
        var set = CoreRangeSet()
        for value: UInt64 in [0, 1, 2, 5, 6, 9] {
            set.insert(value)
        }
        set.removeAll(below: 2)
        XCTAssertEqual(set.ranges, [2..<3, 5..<7, 9..<10])
        set.trim(toCount: 2)
        XCTAssertEqual(set.ranges, [5..<7, 9..<10])
    }

    // MARK: When to acknowledge

    /// RFC 9000 Section 13.2.2: acknowledge at least every second ack-eliciting packet.
    func testEverySecondAckElicitingPacketIsAcknowledgedRightAway() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0])
        XCTAssertFalse(tracker.ackNeeded)
        self.receive(&tracker, [1])
        XCTAssertTrue(tracker.ackNeeded)
        XCTAssertNil(tracker.ackDeadline)
        tracker.onAckSent()
        self.receive(&tracker, [2])
        XCTAssertFalse(tracker.ackNeeded)
    }

    /// RFC 9000 Section 13.2.1: a single ack-eliciting packet is acknowledged within
    /// max_ack_delay.
    func testASingleAckElicitingPacketWaitsAtMostTheMaxAckDelay() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0])
        XCTAssertFalse(tracker.ackNeeded)
        XCTAssertEqual(tracker.ackDeadline, self.now.advanced(by: self.maxAckDelay))
    }

    /// RFC 9000 Section 13.2.1: packets that aren't ack-eliciting are acknowledged only along with
    /// ack-eliciting ones.
    func testPacketsThatAreNotAckElicitingAreNotAcknowledgedOnTheirOwn() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0, 1, 2, 3], isAckEliciting: false)
        XCTAssertFalse(tracker.ackNeeded)
        XCTAssertNil(tracker.ackDeadline)
        // They still are in the next ACK frame.
        XCTAssertTrue(tracker.hasAckToSend)
        XCTAssertEqual(Self.decode(Self.writeAck(tracker, now: self.now))?.ranges, [0...3])
    }

    /// RFC 9000 Section 13.2.1: an ack-eliciting packet that arrives out of order, below the
    /// largest or after a gap, is acknowledged right away.
    func testAnOutOfOrderPacketIsAcknowledgedRightAway() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0])
        tracker.onAckSent()
        // A gap: 1 is missing.
        self.receive(&tracker, [2])
        XCTAssertTrue(tracker.ackNeeded)
        tracker.onAckSent()
        // The missing one, below the largest.
        self.receive(&tracker, [1])
        XCTAssertTrue(tracker.ackNeeded)
    }

    // MARK: ACK frames

    /// RFC 9000 Section 19.3.1: the first range ends at the largest packet number, and each gap
    /// and range is encoded as one less than its length.
    func testTheAckFrameListsTheRangesDescending() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0, 1, 2, 5, 6, 9, 20])
        let ack = Self.decode(Self.writeAck(tracker, now: self.now))
        XCTAssertEqual(ack, DecodedAck(largest: 20, delay: 0, ranges: [20...20, 9...9, 5...6, 0...2]))
    }

    /// RFC 9000 Section 19.3: the ACK Delay is the time since the largest packet arrived, in
    /// microseconds divided by 2 to the power of ack_delay_exponent.
    func testTheAckDelayIsScaledByTheExponent() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0])
        let later = self.now.advanced(by: .microseconds(20_000))
        XCTAssertEqual(Self.decode(Self.writeAck(tracker, now: later))?.delay, 20_000 >> 3)
        XCTAssertEqual(Self.decode(Self.writeAck(tracker, now: later, ackDelayExponent: 0))?.delay, 20_000)
    }

    /// RFC 9000 Section 13.2.4: once an ACK frame was acknowledged, the packet numbers it
    /// reported are no longer sent, and packets below them are duplicates.
    func testAnAcknowledgedAckFrameIsNotReportedAgain() {
        var tracker = CoreAckTracker()
        self.receive(&tracker, [0, 1, 2, 4])
        tracker.onAckAcknowledged(largest: 2)
        XCTAssertEqual(Self.decode(Self.writeAck(tracker, now: self.now))?.ranges, [4...4])
        XCTAssertTrue(tracker.isDuplicate(1))
        XCTAssertFalse(tracker.isDuplicate(3))
        XCTAssertTrue(tracker.isDuplicate(4))
    }

    /// The number of ranges is bounded; the oldest ones go first (RFC 9000 Section 13.2.3).
    func testTheNumberOfRangesIsBounded() {
        var tracker = CoreAckTracker()
        let packetNumbers = (0..<UInt64(CoreAckTracker.maximumRanges + 10)).map { $0 * 2 }
        self.receive(&tracker, packetNumbers)
        guard let ack = Self.decode(Self.writeAck(tracker, now: self.now)) else {
            return XCTFail("No ACK frame")
        }
        XCTAssertEqual(ack.ranges.count, CoreAckTracker.maximumRanges)
        XCTAssertEqual(ack.ranges.first, packetNumbers.last!...packetNumbers.last!)
        let oldest = packetNumbers[packetNumbers.count - CoreAckTracker.maximumRanges]
        XCTAssertEqual(ack.ranges.last, oldest...oldest)
    }
}

#endif
