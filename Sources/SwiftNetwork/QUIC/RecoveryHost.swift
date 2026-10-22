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

/// The connection state that loss recovery reads, and the packets it asks the connection to send.
///
/// Recovery is passed its host explicitly instead of holding a reference to it, so it can be
/// driven by anything that owns the paths and the pending items.
@available(Network 0.1.0, *)
protocol RecoveryHost: AnyObject {
    var now: NetworkClock.Instant { get }
    var qLog: QLog? { get }
    var state: QUICConnectionState { get }
    var isServer: Bool { get }
    var isHandshakeConfirmed: Bool { get }
    var receivedHandshakePacket: Bool { get }
    var isL4SEnabled: Bool { get }
    var remoteAckDelayExponent: Int { get }

    var currentPath: QUICPath? { get }
    func path(for pathID: MultiplexingPathIdentifier) -> QUICPath?
    func applyToAllPaths(_ closure: (QUICPath) -> Void)
    func withCurrentPath(_ block: (borrowing QUICPath) -> Void)
    func withCurrentPath(_ block: (borrowing QUICPath) -> Bool) -> Bool
    func withECN<Result>(_ body: (borrowing ECN) -> Result) -> Result

    func largestAckedPacketNumber(space: PacketNumberSpace) -> PacketNumber
    func setLargestAckedPacketNumber(_ number: PacketNumber, space: PacketNumberSpace)
    func incrementStatistic(_ key: QUICStatistic, by value: Int)

    func withPendingItems<T>(
        for packetNumberSpace: PacketNumberSpace,
        block: (inout PendingItems) -> T
    ) -> T
    func triggerAllStreamsUnblocked()

    func rescheduleTimer(
        identifier: Timer.TimerID,
        fromNow: NetworkDuration,
        timerNow: NetworkClock.Instant,
        in eventContext: inout NetworkContext.EventContext
    )
    func stopTimer(in eventContext: inout NetworkContext.EventContext)

    func acknowledged(
        _ packet: borrowing SentPacketRecord,
        packetNumber: PacketNumber,
        packetNumberSpace: PacketNumberSpace,
        sentPath: QUICPath,
        in eventContext: inout NetworkContext.EventContext
    )
    func sendFramesFromRecovery(
        on path: QUICPath,
        ignoreCongestionWindow: Bool,
        retransmission: Bool,
        discardInitialRecoveryState: inout Bool,
        in eventContext: inout NetworkContext.EventContext
    ) -> NetworkUniqueDeque<SentPacketRecord>
    func retransmitPacket(
        _ packet: borrowing SentPacketRecord,
        discardInitialRecoveryState: inout Bool,
        in eventContext: inout NetworkContext.EventContext
    ) -> NetworkUniqueDeque<SentPacketRecord>
    func retransmitOnePacketForced(
        packet: borrowing SentPacketRecord,
        path: QUICPath,
        discardInitialRecoveryState: inout Bool,
        in eventContext: inout NetworkContext.EventContext
    ) -> NetworkUniqueDeque<SentPacketRecord>
    func sendAllEnqueuedOutboundDatagrams(in eventContext: inout NetworkContext.EventContext)
}

@available(Network 0.1.0, *)
extension QUICConnection: RecoveryHost {
    var remoteAckDelayExponent: Int {
        self.ack.remoteDelayExponent
    }

    func withECN<Result>(_ body: (borrowing ECN) -> Result) -> Result {
        body(self.ecn)
    }

    func incrementStatistic(_ key: QUICStatistic, by value: Int) {
        self.stats.increment(key, by: value)
    }

    func triggerAllStreamsUnblocked() {
        self.applicationPendingItems.triggerAllStreamsUnblocked = true
    }

    func rescheduleTimer(
        identifier: Timer.TimerID,
        fromNow: NetworkDuration,
        timerNow: NetworkClock.Instant,
        in eventContext: inout NetworkContext.EventContext
    ) {
        self.timer.reschedule(identifier: identifier, fromNow: fromNow, timerNow: timerNow, in: &eventContext)
    }

    func stopTimer(in eventContext: inout NetworkContext.EventContext) {
        self.timer.stop(in: &eventContext)
    }
}

#endif
