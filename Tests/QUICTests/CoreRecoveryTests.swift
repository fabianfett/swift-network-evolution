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

/// `CoreRecovery` against a model that scans every sent packet on every ACK.
@available(Network 0.1.0, *)
final class CoreRecoveryTests: XCTestCase {
    private struct Generator: RandomNumberGenerator {
        var state: UInt64

        mutating func next() -> UInt64 {
            self.state &+= 0x9E37_79B9_7F4A_7C15
            var z = self.state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
    }

    /// The sent packets of one space, acknowledged and declared lost by scanning all of them.
    private struct Model {
        struct Packet {
            var number: UInt64
            var timeSent: NetworkClock.Instant
            var size: Int
        }

        var sent: [Packet] = []
        var largestAcknowledged: UInt64?
        var bytesInFlight = 0

        mutating func acknowledge(_ ranges: [ClosedRange<UInt64>]) -> [UInt64] {
            if let largest = ranges.first?.upperBound {
                self.largestAcknowledged = max(self.largestAcknowledged ?? largest, largest)
            }
            let acknowledged = self.sent.filter { packet in ranges.contains { $0.contains(packet.number) } }
            self.sent.removeAll { packet in ranges.contains { $0.contains(packet.number) } }
            self.bytesInFlight -= acknowledged.reduce(0) { $0 + $1.size }
            return acknowledged.map(\.number)
        }

        mutating func detectLost(now: NetworkClock.Instant, lossDelay: NetworkDuration) -> [UInt64] {
            guard let largest = self.largestAcknowledged else { return [] }
            let lost = self.sent.filter { packet in
                packet.number <= largest
                    && (packet.timeSent.advanced(by: lossDelay) <= now || largest >= packet.number + 3)
            }
            self.sent.removeAll { packet in lost.contains { $0.number == packet.number } }
            self.bytesInFlight -= lost.reduce(0) { $0 + $1.size }
            return lost.map(\.number)
        }
    }

    /// Random ACK frames over a window of sent packets, with gaps, repeats and numbers never sent.
    private static func ranges(
        upTo largest: UInt64,
        using generator: inout Generator
    ) -> [ClosedRange<UInt64>] {
        var ranges: [ClosedRange<UInt64>] = []
        var upper = largest
        for _ in 0..<Int.random(in: 1...4, using: &generator) {
            let length = UInt64.random(in: 0...6, using: &generator)
            let lower = upper >= length ? upper - length : 0
            ranges.append(lower...upper)
            let gap = UInt64.random(in: 2...8, using: &generator)
            guard lower >= gap else { break }
            upper = lower - gap
        }
        return ranges
    }

    func testAcknowledgementsAndLossesMatchAFullScan() {
        for seed in UInt64(1)...200 {
            var generator = Generator(state: seed)
            var recovery = CoreRecovery()
            var model = Model()
            var now = NetworkClock.Instant(milliseconds: 1_000)
            var nextPacketNumber: UInt64 = 0
            for round in 0..<60 {
                for _ in 0..<Int.random(in: 0...12, using: &generator) {
                    // Skipped packet numbers are allowed (RFC 9000 Section 12.3).
                    nextPacketNumber += UInt64.random(in: 0...1, using: &generator) == 0 ? 1 : 2
                    let size = Int.random(in: 50...1350, using: &generator)
                    recovery.onPacketSent(
                        CoreSentPacket(
                            packetNumber: nextPacketNumber,
                            timeSent: now,
                            size: size,
                            isAckEliciting: true,
                            isInFlight: true,
                            frames: [.ping]
                        ),
                        in: .applicationData
                    )
                    model.sent.append(Model.Packet(number: nextPacketNumber, timeSent: now, size: size))
                    model.bytesInFlight += size
                }
                now = now.advanced(by: .milliseconds(Int64.random(in: 0...40, using: &generator)))
                guard nextPacketNumber > 0, Bool.random(using: &generator) else { continue }
                let largest = UInt64.random(in: (nextPacketNumber / 2)...nextPacketNumber, using: &generator)
                let ranges = Self.ranges(upTo: largest, using: &generator)

                // The model needs the loss delay as of after this ACK's RTT sample.
                let result = recovery.onAckReceived(
                    ranges: ranges,
                    ackDelay: .zero,
                    in: .applicationData,
                    handshakeConfirmed: true,
                    now: now
                )
                let lossDelay = max(
                    max(recovery.latestRTT, recovery.smoothedRTT) + max(recovery.latestRTT, recovery.smoothedRTT) / 8,
                    .milliseconds(1)
                )
                let acknowledged = model.acknowledge(ranges)
                let lost = acknowledged.isEmpty ? [] : model.detectLost(now: now, lossDelay: lossDelay)

                let context = "seed \(seed), round \(round), ranges \(ranges)"
                XCTAssertEqual(result.acknowledged.map(\.packetNumber), acknowledged, context)
                XCTAssertEqual(result.lost.map(\.packetNumber), lost, context)
                XCTAssertEqual(
                    recovery.spaces[2].sent.map(\.packetNumber),
                    model.sent.map(\.number),
                    context
                )
                XCTAssertEqual(recovery.bytesInFlight, model.bytesInFlight, context)
                XCTAssertEqual(recovery.spaces[2].ackElicitingInFlight, model.sent.count, context)
            }
        }
    }
}

#endif
