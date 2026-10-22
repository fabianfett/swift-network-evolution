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

#if canImport(BasicContainers)
import BasicContainers
internal import DequeModule
#endif

#if canImport(Glibc)
import Glibc
internal import Logging
#elseif canImport(Android)
import Android
internal import Logging
#elseif canImport(Musl)
import Musl
internal import Logging
#elseif canImport(os)
internal import os
#endif

@available(Network 0.1.0, *)
protocol TimerUser {
    var timerID: Timer.TimerID? { get set }
    func timerFired(at timeNow: NetworkClock.Instant, in eventContext: inout NetworkContext.EventContext)
}

// TODO: convert timer to ~Copyable
@available(Network 0.1.0, *)
final class Timer: PrefixedLoggable {
    typealias TimerID = TimerTable.TimerID
    typealias Handler = (NetworkClock.Instant, inout NetworkContext.EventContext) -> Void

    package var log: LogPrefixer
    private var identifier: InstanceIdentifier? = nil
    private var context: NetworkContext? = nil
    private var timerReference: TimerReference
    private var timerCancelled = false
    private var avoidRecalculate = false
    /// Deadlines and wakeup decisions; the timer only adds the handlers and the scheduling.
    private var table: TimerTable
    private var handlers: [(identifier: TimerID, handler: Handler)] = []

    var nextDeadline: NetworkClock.Instant {
        table.nextDeadline
    }

    private var wakeupCompletion: ((inout NetworkContext.EventContext) -> Void)? = nil

    /// See `TimerTable.timerThreshold`.
    static var timerThreshold: NetworkDuration { TimerTable.timerThreshold }

    init(
        identifier: InstanceIdentifier,
        context: NetworkContext,
        timerReference: TimerReference,
        logPrefixer: LogPrefixer
    ) {
        self.log = logPrefixer
        self.table = TimerTable(logPrefixer: logPrefixer)
        self.identifier = identifier
        self.context = context
        self.timerReference = timerReference
    }

    internal init(timerReference: TimerReference, logPrefixer: LogPrefixer) {
        self.log = logPrefixer
        self.table = TimerTable(logPrefixer: logPrefixer)
        self.timerReference = timerReference
    }

    func insert(
        description: String,
        fromNow: NetworkDuration = .zero,
        timerNow: NetworkClock.Instant,
        in eventContext: inout NetworkContext.EventContext,
        closure: @escaping Handler
    ) -> TimerID {
        let identifier = table.insert(description: description, fromNow: fromNow, timerNow: timerNow)
        handlers.append((identifier, closure))
        if !avoidRecalculate {
            recalculate(timerNow, in: &eventContext)
        }
        return identifier
    }

    func remove(_ identifier: TimerID) {
        table.remove(identifier)
        if let index = handlers.firstIndex(where: { $0.identifier == identifier }) {
            handlers.remove(at: index)
        }
    }

    func stop(final: Bool = true, in eventContext: inout NetworkContext.EventContext) {
        if !timerCancelled {
            log.debug("Stopping timer")
            timerCancelled = true
            table.stop(final: false)
            wakeupCompletion = nil
            if let identifier {
                identifier.unscheduleWakeup(
                    timerReference: timerReference,
                    in: &eventContext
                )
            }
        }
        if final {
            table.stop(final: true)
            handlers.removeAll()
            identifier = nil
        }
    }

    private func recalculate(_ now: NetworkClock.Instant, in eventContext: inout NetworkContext.EventContext) {
        switch table.recalculate(now) {
        case .stop:
            stop(final: false, in: &eventContext)
        case .keep:
            return
        case .arm(let delta):
            timerCancelled = false
            if let identifier, let context {
                // The wakeup block is built once and reused for every re-arm, so re-arming costs no
                // allocation. It captures the timer, so the timer holds itself until `stop(final:)`
                // drops the block on teardown.
                if wakeupCompletion == nil {
                    wakeupCompletion = { timerState in
                        self.timerFired(at: context.now, in: &timerState)
                    }
                }
                identifier.scheduleWakeup(
                    context: context,
                    after: delta,
                    timerReference: timerReference,
                    in: &eventContext,
                    wakeupCompletion!
                )
            }
        }
    }

    func reschedule(
        identifier: TimerID,
        fromNow: NetworkDuration,
        timerNow: NetworkClock.Instant,
        in eventContext: inout NetworkContext.EventContext
    ) {
        guard table.reschedule(identifier: identifier, fromNow: fromNow, timerNow: timerNow) else {
            return
        }
        if !avoidRecalculate {
            recalculate(timerNow, in: &eventContext)
        }
    }

    public func timerFired(
        at timeNow: NetworkClock.Instant,
        in eventContext: inout NetworkContext.EventContext
    ) {
        // Timer fired means the kernel woke us up.
        table.wakeupFired()

        if _slowPath(timerCancelled) {
            log.fault("Timer fired after it was cancelled")
            return
        }
        // Due to timer leeway, we might actually be running a bit early, so
        // allow 1ms of leeway.
        let now = timeNow.advanced(by: Timer.timerThreshold)
        var ranOne = false

        avoidRecalculate = true
        log.datapath("Running quic timer, now \(now)")
        var index = 0
        while let expired = table.popExpired(from: &index, now: now) {
            if let handler = handlers.first(where: { $0.identifier == expired })?.handler {
                handler(timeNow, &eventContext)
            }
            ranOne = true
        }

        if _slowPath(!ranOne) {
            let entryCount = table.entries.count
            for i in 0..<entryCount {
                log.error(
                    "Timer [T\(table.entries[i].identifier)] deadline \(table.entries[i].deadline), now \(now)"
                )
            }
            log.fault(
                "Spurious timer at \(now)), next deadline \(nextDeadline), cancelled? \(timerCancelled)"
            )
        }
        recalculate(timeNow, in: &eventContext)
        avoidRecalculate = false
    }
}
#endif
