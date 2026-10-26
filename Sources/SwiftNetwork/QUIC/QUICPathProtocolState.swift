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

    var dcid: QUICConnectionID?  // The DCID we assigned before probing
    var scid: QUICConnectionID?  // Contains the SCID we expect to see once we migrate.

    var pathStatistics = Statistics()

    var initialMSS = 0
    var mss = 0
    var maximumMSS = 0

    struct Flags: OptionSet {
        init(rawValue: Self.RawValue) {
            self.rawValue = rawValue
        }
        var rawValue: UInt16
        static let isInitialPath = Flags(rawValue: 1 << 0)
        static let spinValue = Flags(rawValue: 1 << 1)
        static let reportedIdleEvent = Flags(rawValue: 1 << 2)
    }
    var flags = Flags()

    init() {}
}

#endif
