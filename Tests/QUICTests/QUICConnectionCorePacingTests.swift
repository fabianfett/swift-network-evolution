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

/// Kernel pacing in `QUICConnectionCore` (RFC 9002 Section 7.7): departure times, never delays.
@available(Network 0.1.0, *)
final class QUICConnectionCorePacingTests: XCTestCase {
    private static func configuration(pacing: Bool) -> QUICConnectionCore.Configuration {
        var configuration = QUICConnectionCore.Configuration(tlsOptions: SwiftTLSProtocol.Options())
        configuration.pacingEnabled = pacing
        return configuration
    }

    /// Sends everything `machine` has at `now`, with each datagram's length and departure time.
    private static func drain(
        _ machine: inout QUICConnectionCore,
        now: NetworkClock.Instant
    ) -> [(datagram: [UInt8], departureTime: NetworkClock.Instant?)] {
        var sent: [(datagram: [UInt8], departureTime: NetworkClock.Instant?)] = []
        var buffer = [UInt8](repeating: 0, count: 1500)
        while sent.count < 1000 {
            var span = buffer.mutableSpan
            guard let length = machine.send(into: &span, now: now) else { break }
            sent.append((Array(buffer[0..<length]), machine.departureTime))
        }
        return sent
    }

    // MARK: CorePacer

    func testThePacerStartsAtTheWindowPer100Milliseconds() {
        var pacer = CorePacer()
        pacer.reset(congestionWindow: 12_000, maxDatagramSize: 1200)
        XCTAssertEqual(pacer.rate, 120_000)
        XCTAssertEqual(pacer.burstSize, 1200)
        let now = NetworkClock.Instant(milliseconds: 1_000)
        XCTAssertEqual(pacer.departureTime(ofDatagram: 1200, now: now), now)
        // A full burst of 1200 bytes takes 10 ms at 120 kB/s.
        XCTAssertEqual(pacer.departureTime(ofDatagram: 1200, now: now), now.advanced(by: .milliseconds(10)))
        XCTAssertEqual(pacer.departureTime(ofDatagram: 1200, now: now), now.advanced(by: .milliseconds(20)))
    }

    func testThePacerPacesTheWindowPerRTTAndTwiceThatInSlowStart() {
        var pacer = CorePacer()
        pacer.update(congestionWindow: 20_000, inSlowStart: true, smoothedRTT: .milliseconds(10))
        XCTAssertEqual(pacer.rate, 4_000_000)
        XCTAssertEqual(pacer.burstSize, 4_000_000 >> 10)
        pacer.update(congestionWindow: 20_000, inSlowStart: false, smoothedRTT: .milliseconds(10))
        XCTAssertEqual(pacer.rate, 2_000_000)
        XCTAssertEqual(pacer.burstSize, 2_000_000 >> 10)
        // A zero RTT can't divide; it counts as the startup RTT.
        pacer.update(congestionWindow: 20_000, inSlowStart: false, smoothedRTT: .zero)
        XCTAssertEqual(pacer.rate, 200_000)
    }

    func testABurstGoesOutTogetherAndTheNextOneAnIntervalLater() {
        var pacer = CorePacer()
        pacer.update(congestionWindow: 20_000, inSlowStart: false, smoothedRTT: .milliseconds(10))
        let burstSize = pacer.burstSize
        let now = NetworkClock.Instant(milliseconds: 1_000)
        var departures: [NetworkClock.Instant] = []
        for _ in 0..<6 {
            departures.append(pacer.departureTime(ofDatagram: 1000, now: now))
        }
        // 1953-byte bursts: two datagrams fit before the burst is full.
        XCTAssertEqual(burstSize, 1953)
        let interval = pacer.interval(forBytes: 2000)
        XCTAssertEqual(interval, .microseconds(1000))
        XCTAssertEqual(
            departures,
            [now, now, now + interval, now + interval, now + interval * 2, now + interval * 2]
        )
    }

    func testABurstNeverLeavesBeforeNow() {
        var pacer = CorePacer()
        pacer.reset(congestionWindow: 12_000, maxDatagramSize: 1200)
        let start = NetworkClock.Instant(milliseconds: 1_000)
        XCTAssertEqual(pacer.departureTime(ofDatagram: 1200, now: start), start)
        // Long after the burst, the next one goes out right away.
        let later = start.advanced(by: .seconds(1))
        XCTAssertEqual(pacer.departureTime(ofDatagram: 1200, now: later), later)
    }

    func testABurstIntervalIsAtMost10Milliseconds() {
        var pacer = CorePacer()
        XCTAssertEqual(pacer.interval(forBytes: 1200), Constants.maxBurstIntervalKernelPacing, "no rate yet")
        pacer.update(congestionWindow: 2400, inSlowStart: false, smoothedRTT: .seconds(10))
        XCTAssertEqual(pacer.interval(forBytes: 1200), Constants.maxBurstIntervalKernelPacing)
    }

    func testResettingCongestionControlResetsThePacer() {
        var recovery = CoreRecovery(pacingEnabled: true)
        recovery.pacer?.update(congestionWindow: 50_000, inSlowStart: true, smoothedRTT: .milliseconds(1))
        recovery.resetCongestionControl()
        XCTAssertEqual(recovery.pacer?.rate, UInt64(recovery.congestionWindow) * 10)
        XCTAssertEqual(recovery.pacer?.burstSize, recovery.maxDatagramSize)
        XCTAssertNil(CoreRecovery().pacer)
    }

    // MARK: Lockstep

    func testDepartureTimesAreMonotonicAndSpacedByBurstOverRate() throws {
        var pair = LockstepPair(
            clientConfiguration: Self.configuration(pacing: true),
            serverConfiguration: Self.configuration(pacing: true)
        )
        // Nothing of the handshake is paced.
        let initial = Self.drain(&pair.client, now: pair.now)
        XCTAssertFalse(initial.isEmpty)
        XCTAssertTrue(initial.allSatisfy { $0.departureTime == nil })
        pair.toServer += initial.map(\.datagram)
        pair.exchange()
        XCTAssertTrue(pair.client.isHandshakeConfirmed)

        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 60_000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        // The ACKs of the handshake set the rate; nothing is acknowledged while this drains.
        let pacer = try XCTUnwrap(pair.client.recovery.pacer)
        let sent = Self.drain(&pair.client, now: pair.now)
        XCTAssertGreaterThan(sent.count, 3)
        let departures = try sent.map { try XCTUnwrap($0.departureTime) }

        // A burst fills up to the burst size, then the next one leaves the burst's bytes over the
        // rate later. The clock stands still, so no burst is pulled forward to now.
        var burstStart = pacer.burstStart ?? pair.now
        var burstBytes = pacer.burstStart == nil ? 0 : pacer.burstBytes
        var bursts = 0
        for (index, datagram) in sent.enumerated() {
            if burstBytes >= pacer.burstSize && !(index == 0 && pacer.burstStart == nil) {
                let interval = pacer.interval(forBytes: burstBytes)
                XCTAssertGreaterThan(interval, .zero)
                XCTAssertLessThan(interval, Constants.maxBurstIntervalKernelPacing, "the rate decides, not the cap")
                burstStart = burstStart + interval
                burstBytes = 0
                bursts += 1
            }
            burstBytes += datagram.datagram.count
            XCTAssertEqual(departures[index], burstStart, "datagram \(index)")
            XCTAssertGreaterThanOrEqual(departures[index], pair.now)
            if index > 0 {
                XCTAssertGreaterThanOrEqual(departures[index], departures[index - 1], "monotonic at \(index)")
            }
        }
        XCTAssertGreaterThan(bursts, 1, "the data spans more than one burst")
    }

    func testAConnectionWithoutPacingHasNoDepartureTimes() throws {
        var pair = LockstepPair()
        pair.exchange()
        XCTAssertNil(pair.client.recovery.pacer)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 20_000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        let sent = Self.drain(&pair.client, now: pair.now)
        XCTAssertFalse(sent.isEmpty)
        XCTAssertTrue(sent.allSatisfy { $0.departureTime == nil })
    }

    func testAcknowledgementsRaiseThePacingRate() throws {
        var pair = LockstepPair(clientConfiguration: Self.configuration(pacing: true))
        pair.exchange()
        let before = try XCTUnwrap(pair.client.recovery.pacer)
        let streamID = try XCTUnwrap(pair.client.openStream(bidirectional: true))
        let payload = [UInt8](repeating: 0x42, count: 60_000)
        pair.client.write(payload.span.bytes, to: streamID, fin: true)
        pair.exchange()
        let after = try XCTUnwrap(pair.client.recovery.pacer)
        XCTAssertGreaterThan(pair.client.recovery.congestionWindow, CoreRecovery.initialWindow(maxDatagramSize: 1200))
        XCTAssertGreaterThan(after.rate, before.rate, "slow start grew the window")
        // The lockstep clock stands still, so the RTT is zero, which counts as the startup RTT.
        let rtt = pair.client.recovery.smoothedRTT.microseconds
        XCTAssertEqual(
            after.rate,
            UInt64(pair.client.recovery.congestionWindow * 2) * 1_000_000 / UInt64(rtt > 0 ? rtt : 100_000),
            "twice the window per smoothed RTT in slow start"
        )
    }
}

#endif
