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

/// The protocol state of one QUIC path: its state, connection IDs, statistics and MSS.
@available(Network 0.1.0, *)
struct QUICPathProtocolState: ~Copyable {
    var state: QUICPathState = QUICPathState()
    var priority: Int = 0  // Relative priority to other paths, used to gate migration decisions

    var dcid: QUICConnectionID?  // The DCID we assigned before probing
    var scid: QUICConnectionID?  // Contains the SCID we expect to see once we migrate.

    var pathStatistics = Statistics()

    var initialMSS = 0
    var mss = 0
    var maximumMSS = 0
    var minimumMSS = 0

    struct Flags: OptionSet {
        init(rawValue: Self.RawValue) {
            self.rawValue = rawValue
        }
        var rawValue: UInt16
        static let isInitialPath = Flags(rawValue: 1 << 1)
        static let isPrimaryPath = Flags(rawValue: 1 << 2)
        static let spinValue = Flags(rawValue: 1 << 3)
        static let isPreferredAddress = Flags(rawValue: 1 << 5)
        static let hasPreAssignedCIDs = Flags(rawValue: 1 << 8)
        static let reportedIdleEvent = Flags(rawValue: 1 << 11)
    }
    var flags = Flags()

    init() {}
}

#endif
