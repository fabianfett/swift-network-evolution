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

/// Datagram packetization layer path MTU discovery of one path (RFC 9000 Section 14.3, RFC 8899).
///
/// Probes are PING and PADDING up to the next size of a ladder of common MTUs. An acknowledged
/// probe raises the largest datagram the path carries; three lost probes of one size end the
/// search, which starts over after an interval. More than three PTOs in a row fall back to the
/// base size, in case the path no longer carries the larger datagrams (RFC 8899 Section 4.3).
///
/// Sizes here are MTUs, including the IP and UDP headers; datagram sizes are UDP payloads.
@available(Network 0.1.0, *)
struct CorePMTUD {
    static let minimumMTU = 1280
    static let maximumMTU = 9216
    /// Lost probes of one size before the search ends (MAX_PROBES of RFC 8899 Section 5.1.2).
    static let maximumProbes = 3
    /// PTOs in a row after which the path may black-hole the larger datagrams.
    static let blackholeThreshold = 3
    /// Packets larger than the base size lost in a row, with none acknowledged in between, after
    /// which the path may black-hole them. PTOs alone miss a black hole that smaller packets,
    /// such as ACKs and the ends of streams, still get through (RFC 8899 Section 4.3).
    static let blackholeLosses = 10
    /// The sizes the search climbs, largest first.
    static let ladder = [9216, 1500, 1492, 1450, 1430, 1410, 1390, 1370, 1350, 1300, 1280]

    /// The size of the IP and UDP headers of the path's datagrams.
    let ipUDPHeaderSize: Int
    /// The datagram size the path starts with, and falls back to (BASE_PLPMTU).
    let baseDatagramSize: Int
    /// The largest datagram, including headers, the path is known to carry.
    private(set) var currentMTU: Int
    /// The largest size the search may reach: the interface MTU and the peer's
    /// `max_udp_payload_size`.
    private(set) var maximumMTU = 0
    /// The size the next probe has.
    private(set) var probeMTU = 0
    /// A probe of `probeMTU` is due.
    private(set) var probePending = false
    private(set) var failedProbes = 0
    private(set) var isSearching = false
    /// When the search starts over, once it ended (PMTU_RAISE_TIMER).
    private(set) var raiseDeadline: NetworkClock.Instant?
    /// Probes with a lower packet number belong to an earlier search, perhaps on another path.
    private var firstPacketNumber: UInt64 = 0

    init(baseDatagramSize: Int, ipUDPHeaderSize: Int) {
        self.baseDatagramSize = baseDatagramSize
        self.ipUDPHeaderSize = ipUDPHeaderSize
        self.currentMTU = baseDatagramSize &+ ipUDPHeaderSize
    }

    /// The largest UDP payload the path carries.
    var maxDatagramSize: Int {
        self.currentMTU &- self.ipUDPHeaderSize
    }

    /// The UDP payload of the next probe.
    var probeDatagramSize: Int {
        self.probeMTU &- self.ipUDPHeaderSize
    }

    /// Starts searching, once the handshake is confirmed or on a new path.
    ///
    /// - Parameters:
    ///   - interfaceMTU: The MTU of the path's interface; zero if unknown, which allows 1280.
    ///   - peerMaxUDPPayloadSize: The peer's `max_udp_payload_size`.
    ///   - firstPacketNumber: The next packet number of the application data space.
    mutating func start(interfaceMTU: Int, peerMaxUDPPayloadSize: Int, firstPacketNumber: UInt64) {
        let interfaceMTU = max(min(interfaceMTU, Self.maximumMTU), Self.minimumMTU)
        self.maximumMTU = min(interfaceMTU, self.ipUDPHeaderSize &+ peerMaxUDPPayloadSize, Self.maximumMTU)
        self.firstPacketNumber = firstPacketNumber
        self.failedProbes = 0
        self.raiseDeadline = nil
        self.isSearching = true
        self.updateProbeSize()
    }

    /// Picks the next probe size, or ends the search if there is no larger one.
    private mutating func updateProbeSize() {
        if self.failedProbes == 0 {
            self.probeMTU = min(Self.nextMTU(above: self.currentMTU), self.maximumMTU)
        }
        if self.probeMTU <= self.currentMTU {
            // Nothing larger is allowed: the search is done, and there is nothing to raise.
            self.isSearching = false
            self.probePending = false
            return
        }
        self.probePending = true
    }

    /// The next larger size of the ladder, or zero above its top.
    static func nextMTU(above mtu: Int) -> Int {
        var larger = 0
        for size in Self.ladder {
            guard size > mtu else { break }
            larger = size
        }
        return larger
    }

    mutating func probeSent() {
        self.probePending = false
    }

    /// A probe of `datagramSize` with `packetNumber` was acknowledged. Returns the new largest
    /// datagram size, if it grew.
    mutating func probeAcknowledged(
        datagramSize: Int,
        packetNumber: UInt64,
        interval: NetworkDuration,
        now: NetworkClock.Instant
    ) -> Int? {
        let mtu = datagramSize &+ self.ipUDPHeaderSize
        guard self.isSearching, packetNumber >= self.firstPacketNumber, mtu > self.currentMTU else { return nil }
        self.currentMTU = mtu
        self.failedProbes = 0
        if mtu < self.maximumMTU {
            self.updateProbeSize()
        } else {
            self.complete(interval: interval, now: now)
        }
        return self.maxDatagramSize
    }

    /// A probe was declared lost: it is sent again, up to ``maximumProbes`` times.
    mutating func probeLost(datagramSize: Int, packetNumber: UInt64, interval: NetworkDuration, now: NetworkClock.Instant)
    {
        let mtu = datagramSize &+ self.ipUDPHeaderSize
        guard self.isSearching, packetNumber >= self.firstPacketNumber, mtu == self.probeMTU else { return }
        self.failedProbes &+= 1
        if self.failedProbes >= Self.maximumProbes {
            self.complete(interval: interval, now: now)
        } else {
            self.probePending = true
        }
    }

    private mutating func complete(interval: NetworkDuration, now: NetworkClock.Instant) {
        self.isSearching = false
        self.probePending = false
        self.failedProbes = 0
        self.raiseDeadline = self.currentMTU < self.maximumMTU ? now.advanced(by: interval) : nil
    }

    /// The raise timer fired: the search goes on from the current size.
    mutating func raiseTimerFired(firstPacketNumber: UInt64) {
        self.raiseDeadline = nil
        self.firstPacketNumber = firstPacketNumber
        self.failedProbes = 0
        self.isSearching = true
        self.updateProbeSize()
    }

    /// Falls back to the base size, and searches again from there. Returns whether the size
    /// shrank.
    mutating func enterBlackholeDetection(firstPacketNumber: UInt64) -> Bool {
        guard self.maxDatagramSize > self.baseDatagramSize else { return false }
        self.currentMTU = self.baseDatagramSize &+ self.ipUDPHeaderSize
        self.firstPacketNumber = firstPacketNumber
        self.failedProbes = 0
        self.raiseDeadline = nil
        self.isSearching = true
        self.updateProbeSize()
        return true
    }
}

@available(Network 0.1.0, *)
extension QUICConnectionCore {
    /// The largest datagram ``send(into:on:now:)`` may write on the active path right now: its
    /// path MTU, or a PMTUD probe that is due. The driver hands buffers at least this large.
    public var datagramCapacity: Int {
        guard let pmtud = self.paths[self.activePath]?.pmtud, pmtud.probePending else {
            return self.maxDatagramSize
        }
        return max(self.maxDatagramSize, pmtud.probeDatagramSize)
    }

    /// Tells the core the MTU of a path's interface, which caps its PMTUD; zero if unknown.
    public mutating func setInterfaceMTU(_ mtu: Int, on path: CorePathID) {
        if self.paths[path] == nil {
            // As a datagram arriving on it would.
            self.paths[path] = CorePath(id: path, isValidated: false)
        }
        self.paths[path]!.interfaceMTU = mtu
    }

    /// Starts PMTUD on the active path, once the handshake is confirmed.
    mutating func startPMTUD() {
        guard self.configuration.pmtudEnabled, self.isHandshakeConfirmed, var path = self.paths[self.activePath] else {
            return
        }
        let peerLimit =
            self.peerTransportParameters?.intValue(.maxUDPPayloadSize) ?? Int(TransportParameters.maxUDPPayloadSize)
        var pmtud =
            path.pmtud
            ?? CorePMTUD(
                baseDatagramSize: self.configuration.maxDatagramSize,
                ipUDPHeaderSize: self.configuration.ipUDPHeaderSize
            )
        pmtud.start(
            interfaceMTU: path.interfaceMTU ?? self.configuration.interfaceMTU,
            peerMaxUDPPayloadSize: peerLimit,
            firstPacketNumber: UInt64(self.protector.getPacketNumber(for: .applicationData).value)
        )
        path.pmtud = pmtud
        self.paths[self.activePath] = path
        self.log.debug("PMTUD up to \(pmtud.maximumMTU), from \(pmtud.currentMTU)")
    }

    var pmtudDeadline: NetworkClock.Instant? {
        self.paths[self.activePath]?.pmtud?.raiseDeadline
    }

    mutating func handlePMTUDTimeout(now: NetworkClock.Instant) {
        guard let deadline = self.pmtudDeadline, now >= deadline else { return }
        self.paths[self.activePath]?.pmtud?.raiseTimerFired(
            firstPacketNumber: UInt64(self.protector.getPacketNumber(for: .applicationData).value)
        )
    }

    /// Uses `size` as the largest datagram of the active path: for packets and the congestion
    /// controller's window arithmetic (RFC 9002 Section 7.2).
    mutating func setMaxDatagramSize(_ size: Int) {
        self.maxDatagramSize = size
        self.recovery.maxDatagramSizeChanged(to: size)
    }

    mutating func pmtudProbeAcknowledged(datagramSize: Int, packetNumber: UInt64, now: NetworkClock.Instant) {
        guard
            let raised = self.paths[self.activePath]?.pmtud?.probeAcknowledged(
                datagramSize: datagramSize,
                packetNumber: packetNumber,
                interval: self.configuration.pmtudInterval,
                now: now
            )
        else {
            return
        }
        self.log.info("PMTUD probe of \(datagramSize) bytes acknowledged")
        self.setMaxDatagramSize(raised)
    }

    mutating func pmtudProbeLost(datagramSize: Int, packetNumber: UInt64, now: NetworkClock.Instant) {
        self.log.debug("PMTUD probe of \(datagramSize) bytes lost")
        self.paths[self.activePath]?.pmtud?.probeLost(
            datagramSize: datagramSize,
            packetNumber: packetNumber,
            interval: self.configuration.pmtudInterval,
            now: now
        )
    }

    /// A packet that is larger than the base size was acknowledged or lost; enough of them lost
    /// in a row mean a black hole.
    mutating func pmtudLargePacket(acknowledged: Bool) {
        guard !acknowledged else {
            self.pmtudLargePacketsLost = 0
            return
        }
        self.pmtudLargePacketsLost &+= 1
        if self.pmtudLargePacketsLost >= CorePMTUD.blackholeLosses {
            self.enterPMTUDBlackholeDetection()
        }
    }

    /// After more than ``CorePMTUD/blackholeThreshold`` PTOs in a row, the path may have stopped
    /// carrying the larger datagrams: back to the base size.
    mutating func checkPMTUDBlackhole() {
        guard self.recovery.ptoCount > CorePMTUD.blackholeThreshold else { return }
        self.enterPMTUDBlackholeDetection()
    }

    private mutating func enterPMTUDBlackholeDetection() {
        self.pmtudLargePacketsLost = 0
        guard self.configuration.pmtudEnabled,
            self.paths[self.activePath]?.pmtud?.enterBlackholeDetection(
                firstPacketNumber: UInt64(self.protector.getPacketNumber(for: .applicationData).value)
            ) == true,
            let size = self.paths[self.activePath]?.pmtud?.maxDatagramSize
        else {
            return
        }
        self.log.info("PMTUD: the path black-holes larger datagrams, back to \(size) bytes")
        self.setMaxDatagramSize(size)
    }

    /// Whether a PMTUD probe may go out now (RFC 9000 Section 14.4): it is due, nothing but
    /// stream data waits, the congestion window has room, and, unless the cost is ignored, the
    /// data queued is enough to make up for the probe.
    func pmtudProbeSize(limit: Int) -> Int? {
        guard self.configuration.pmtudEnabled, self.isHandshakeConfirmed, case .established = self.state,
            let pmtud = self.paths[self.activePath]?.pmtud, pmtud.probePending
        else {
            return nil
        }
        let size = pmtud.probeDatagramSize
        guard size <= limit, !self.hasControlFramesToSend, self.recovery.availableCongestionWindow >= size else {
            return nil
        }
        if self.configuration.pmtudIgnoreCost { return size }
        guard self.recovery.availableCongestionWindow >= CorePMTUD.maximumProbes &* size else { return nil }
        // Probing pays off if the bigger packets save at least a probe's worth of headers.
        var queued = 0
        for id in self.streams.sendQueue {
            queued &+= Int(truncatingIfNeeded: self.streams.streams[id]?.send.unsentCount ?? 0)
        }
        let headers = pmtud.ipUDPHeaderSize &+ 1 &+ Self.tagLength &+ QUICConnectionID.maximumSize &+ 4
        let saved = (queued / pmtud.currentMTU &- queued / pmtud.probeMTU) &* headers
        return saved >= pmtud.probeMTU ? size : nil
    }

    /// Frames other than stream data that wait to go out in 1-RTT packets.
    private var hasControlFramesToSend: Bool {
        self.acks[.applicationData].ackNeeded || self.handshakeDonePending || self.keepAlivePending
            || self.maxDataPending || self.streams.maxStreamsBidirectionalPending
            || self.streams.maxStreamsUnidirectionalPending || self.pingPending
            || self.paths[self.activePath]?.hasProbingFramesToSend == true || !self.datagramsToSend.isEmpty
            || self.hasConnectionIDFramesToSend || self.probesPending[Int(PacketNumberSpace.applicationData.rawValue)] > 0
    }
}

#endif
