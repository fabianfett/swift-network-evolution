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

/// The deadlines of a connection's timers.
///
/// Pure bookkeeping: it decides when the connection needs to wake up and which timers have expired,
/// but neither schedules wakeups nor runs timer handlers itself.
@available(Network 0.1.0, *)
package struct TimerTable: ~Copyable, PrefixedLoggable {
    package typealias TimerID = UInt16

    package struct Entry {
        package let identifier: TimerID
        package var deadline: NetworkClock.Instant = .zero
        package let description: String

        package var isEnabled: Bool {
            deadline != .zero
        }

        mutating func disable() {
            deadline = .zero
        }

        mutating func schedule(fromNow: NetworkDuration, timerNow: NetworkClock.Instant) {
            // `.zero` is the disabled sentinel that `isEnabled` reads, so it cannot also mean a
            // deadline.
            precondition(fromNow != .zero)
            self.deadline = timerNow.advanced(by: fromNow)
        }
    }

    /// What the owner of the table must do with its wakeup after a deadline changed.
    package enum WakeupAction: Equatable {
        /// No timer has a deadline; cancel any pending wakeup.
        case stop
        /// The pending wakeup is close enough to the earliest deadline.
        case keep
        /// Schedule a wakeup `delay` from now.
        case arm(delay: NetworkDuration)
    }

    private enum WakeupState {
        case idle
        case armed(NetworkClock.Instant)
    }

    /// How far a deadline may move before the pending wakeup is re-armed.
    ///
    /// A deadline that shifts from e.g. 5ms out to 4.5ms out keeps the wakeup it already has, so this
    /// bounds re-arm precision independently of what the scheduler can express: the scheduler takes
    /// a `NetworkDuration` and so resolves nanoseconds, but a *revision* smaller than this is still
    /// ignored. Tightening it trades re-arms for precision and wants a benchmark behind it.
    ///
    /// It also decides whether that coalescing is attempted at all. A deadline nearer than this
    /// always re-arms, because tolerating up to a millisecond of error would dominate it: half a
    /// millisecond out, a coalesced wakeup could land after the deadline had already passed.
    package static let timerThreshold = NetworkDuration.milliseconds(1)

    package var log: LogPrefixer
    private var nextID: TimerID = 1
    private(set) package var entries: NetworkUniqueDeque<Entry> = .init(minimumCapacity: 4)
    private var wakeup: WakeupState = .idle
    #if DatapathLogging
    private let extraDebugging = true
    #else
    private let extraDebugging = false
    #endif

    package init(logPrefixer: LogPrefixer) {
        self.log = logPrefixer
    }

    /// The deadline of the pending wakeup, or `.zero` if there is none.
    package var nextDeadline: NetworkClock.Instant {
        switch wakeup {
        case .armed(let instant):
            return instant
        case .idle:
            return .zero
        }
    }

    package mutating func insert(
        description: String,
        fromNow: NetworkDuration = .zero,
        timerNow: NetworkClock.Instant
    ) -> TimerID {
        let identifier = nextID
        var entry = Entry(identifier: nextID, description: description)
        if fromNow != .zero {
            entry.schedule(fromNow: fromNow, timerNow: timerNow)
        }
        entries.append(entry)
        nextID += 1
        log.datapath("Added timer [T\(identifier)]")
        return identifier
    }

    package mutating func remove(_ identifier: TimerID) {
        // In theory, this should use find(), but that swaps entries which we don't want to do here.
        let entryCount = entries.count
        for i in 0..<entryCount {
            if entries[i].identifier == identifier {
                entries.remove(at: i)
                break
            }
        }
        log.datapath("Removing timer [T\(identifier)]")
    }

    /// Forgets the pending wakeup and, if `final`, all timers.
    package mutating func stop(final: Bool) {
        wakeup = .idle
        if final {
            entries.removeAll()
        }
    }

    /// Records that the pending wakeup fired.
    package mutating func wakeupFired() {
        wakeup = .idle
    }

    /// Updates the deadline of a timer. Returns `false` if nothing changed.
    package mutating func reschedule(
        identifier: TimerID,
        fromNow: NetworkDuration,
        timerNow: NetworkClock.Instant
    ) -> Bool {
        guard let index = find(identifier) else {
            return false
        }
        if fromNow == .zero {
            guard entries[index].isEnabled else {
                return false
            }
            entries[index].disable()
        } else {
            entries[index].schedule(fromNow: fromNow, timerNow: timerNow)
        }
        return true
    }

    /// Disables and returns the next expired timer at or after `index`, advancing `index` past it.
    ///
    /// Handlers run between calls may reschedule timers, which reorders entries; calling this in a
    /// loop visits the entries in the same order as walking them while handlers run.
    package mutating func popExpired(from index: inout Int, now: NetworkClock.Instant) -> TimerID? {
        while index < entries.count {
            if extraDebugging {
                if entries[index].isEnabled && entries[index].deadline > now {
                    log.datapath(
                        "Timer [T\(entries[index].identifier)] desc \(entries[index].description) has deadline \(entries[index].deadline) > now \(now)"
                    )
                }
            }
            defer { index += 1 }
            if entries[index].isEnabled && entries[index].deadline <= now {
                if extraDebugging {
                    log.datapath(
                        "Calling timer closure for [T\(entries[index].identifier)] (\(entries[index].description)) (deadline \(entries[index].deadline) <= now \(now))"
                    )
                }
                entries[index].disable()
                return entries[index].identifier
            }
        }
        return nil
    }

    /// Decides how the wakeup has to change for the earliest deadline, and records the new wakeup.
    package mutating func recalculate(_ now: NetworkClock.Instant) -> WakeupAction {
        if extraDebugging {
            let entryCount = entries.count
            for i in 0..<entryCount {
                if entries[i].isEnabled {
                    var fromNow: NetworkDuration = .zero
                    if entries[i].deadline > now {
                        fromNow = now.duration(to: entries[i].deadline)
                    }
                    log.datapath(
                        "Timer [T\(entries[i].identifier)] desc \(entries[i].description) deadline \(entries[i].deadline) (\(fromNow) from now)"
                    )
                } else {
                    log.datapath(
                        "Timer [T\(entries[i].identifier)] desc \(entries[i].description) (no deadline)"
                    )
                }
            }
        }
        let entryCount = entries.count
        var earliestDeadline: NetworkClock.Instant? = nil
        for i in 0..<entryCount {
            if !entries[i].isEnabled {
                continue
            }
            if earliestDeadline == nil {
                earliestDeadline = entries[i].deadline
            } else if let compareDeadline = earliestDeadline, compareDeadline > entries[i].deadline {
                earliestDeadline = entries[i].deadline
            }
        }

        guard let earliestDeadline else {
            log.debug("No more timers to run")
            return .stop
        }

        var delta = now.duration(to: earliestDeadline)

        // Don't allow times in the past
        if delta < .zero {
            delta = .zero
        }

        // If the timer is over one millisecond in the future,
        // check if it is redundant with the existing deadline (nextDeadline).
        // This optimisation is only valid if there's a pending wakeup, otherwise
        // the timer may never fire.
        if case .armed(let nextDeadline) = wakeup, delta > Self.timerThreshold {
            let deadlineDifference = earliestDeadline.duration(to: nextDeadline)
            if deadlineDifference < Self.timerThreshold && deadlineDifference > (Self.timerThreshold * -1) {
                // Timer is already set to within a millisecond of where it needs to be, don't schedule it
                log.datapath("Timer already scheduled")
                return .keep
            }
        }

        let oldDeadline = nextDeadline
        wakeup = .armed(now + delta)
        log.datapath(
            "Arming timer for the next \(delta) (now \(now)), new deadline \(nextDeadline) old deadline \(oldDeadline)"
        )
        return .arm(delay: delta)
    }

    private mutating func find(_ identifier: TimerID) -> Int? {
        let entryCount = entries.count
        for i in 0..<entryCount {
            if entries[i].identifier == identifier {
                if i != 0 {
                    entries.swapAt(0, i)
                }
                return 0
            }
        }
        return nil
    }
}
