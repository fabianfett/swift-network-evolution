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

#if NETWORK_EMBEDDED
// QUICPreferences for Embedded is small subset of preferences based on what is currently used in the stack otherwise.
struct QUICPreferences {
    static let shared = QUICPreferences()
    let pacePackets: Bool = false

    let maxConcurrentStreams: Int? = nil
    let initialMaxData: Int? = nil
    let initialMaxStreamBidirectionalLocalData: Int? = nil

    private init() {}
}
#else
@available(Network 0.1.0, *)
struct QUICPreferences: ~Copyable, Sendable {
    static let shared = QUICPreferences()

    let pacePackets: Bool
    let quiclogDirectory: String

    // Flow Control
    let maxConcurrentStreams: Int?
    let initialMaxData: Int?
    let initialMaxStreamBidirectionalLocalData: Int?

    private init() {
        pacePackets = QUICPreferences.findSetting("pace_packets", defaultValue: false)
        quiclogDirectory = QUICPreferences.findSetting("quiclog_directory", defaultValue: "")

        // Flow Control
        maxConcurrentStreams = QUICPreferences.findSetting("max_concurrent_streams", defaultValue: nil)
        initialMaxData = QUICPreferences.findSetting("initial_max_data", defaultValue: nil)
        initialMaxStreamBidirectionalLocalData = QUICPreferences.findSetting(
            "initial_max_stream_data_bidi_local",
            defaultValue: nil
        )
    }

    #if !NETWORK_PRIVATE
    static func findSetting<T>(_ settingName: String, defaultValue: T) -> T {
        defaultValue
    }
    #endif
}
#endif
#endif
