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

// MARK: FlowControlGlobals

// FlowControlGlobals assumes that it is only setting a static collection of constants.
@available(Network 0.1.0, *)
struct FlowControlGlobals: ~Copyable {

    // Flow Control Constants
    static let sendQueueFactor: UInt64 = 10
    #if NETWORK_EMBEDDED
    static private let highWaterMarkMax = 50 * 1024  // 50KB
    static private let initialReceiveSpace = 50 * 1024  // 50KB
    #else
    static private let highWaterMarkMax = 4 * 1024 * 1024  // 4MB
    static private let initialReceiveSpace = 2 * 1024 * 1024  // 2MB
    #endif

    // N.B.: values are different for systems with less than 4GB of RAM.
    static private let defaultMaxStreams = 8
    static private let defaultMaxConcurrentStreams = defaultMaxStreams
    static private let defaultMaxBidirectionalStreams = defaultMaxStreams
    static private let defaultMaxUnidirectionalStreams = defaultMaxStreams

    // Flow Control Globals
    static let shared = FlowControlGlobals()

    let initialMaxBidirectionalStreamLocalData: Int
    let initialMaxBidirectionalStreamRemoteData: Int
    let initialMaxUnidirectionalStreamData: Int
    let initialMaxData: Int

    let maxConcurrentStreams: Int
    let streamReceiveHighWaterMarkMax: Int
    let streamSendHighWaterMarkMax: Int
    let initialStreamReceiveSpace: Int
    let initialStreamSendSpace: Int

    let connectionReceiveHighWaterMarkMax: Int
    let connectionSendHighWaterMarkMax: Int
    let initialConnectionReceiveSpace: Int
    let initialConnectionSendSpace: Int

    private init() {
        let isHighMemorySystem = System.isHighMemory()

        // maximum concurrent streams
        if let maxConcurrentStreams = QUICPreferences.shared.maxConcurrentStreams {
            self.maxConcurrentStreams = maxConcurrentStreams
        } else if isHighMemorySystem {
            maxConcurrentStreams = FlowControlGlobals.defaultMaxConcurrentStreams
        } else {
            maxConcurrentStreams = FlowControlGlobals.defaultMaxConcurrentStreams / 2
        }

        // stream receive & send high water mark max
        if let highWaterMarkMax = QUICPreferences.shared.streamMaxReceiveWindow {
            streamReceiveHighWaterMarkMax = highWaterMarkMax
            streamSendHighWaterMarkMax = highWaterMarkMax
        } else if isHighMemorySystem {
            streamReceiveHighWaterMarkMax = FlowControlGlobals.highWaterMarkMax
            streamSendHighWaterMarkMax = FlowControlGlobals.highWaterMarkMax
        } else {
            streamReceiveHighWaterMarkMax = FlowControlGlobals.highWaterMarkMax / 2
            streamSendHighWaterMarkMax = FlowControlGlobals.highWaterMarkMax / 2
        }

        // connection receive & send high water mark max
        connectionReceiveHighWaterMarkMax = streamReceiveHighWaterMarkMax * maxConcurrentStreams
        connectionSendHighWaterMarkMax = streamSendHighWaterMarkMax * maxConcurrentStreams

        // initial max data
        if let initialMaxData = QUICPreferences.shared.initialMaxData {
            self.initialMaxData = initialMaxData
        } else {
            initialMaxData = FlowControlGlobals.initialReceiveSpace * maxConcurrentStreams
        }

        // initial stream receive space
        if let initialStreamReceiveSpace = QUICPreferences.shared.initialStreamReceiveSpace {
            self.initialStreamReceiveSpace = initialStreamReceiveSpace
        } else {
            initialStreamReceiveSpace = FlowControlGlobals.initialReceiveSpace
        }

        // initial connection receive & send space
        initialStreamSendSpace = Int(FlowControlGlobals.sendQueueFactor) * Constants.initialMSS
        initialConnectionSendSpace = initialStreamSendSpace * maxConcurrentStreams
        if let initialConnectionReceiveSpace = QUICPreferences.shared.initialConnectionReceiveSpace {
            self.initialConnectionReceiveSpace = initialConnectionReceiveSpace
        } else {
            initialConnectionReceiveSpace = initialStreamReceiveSpace
        }

        // initial max bidirectional stream local data
        if let initialMaxBidirectionalStreamLocalData = QUICPreferences.shared
            .initialMaxStreamBidirectionalLocalData
        {
            self.initialMaxBidirectionalStreamLocalData = initialMaxBidirectionalStreamLocalData
        } else {
            initialMaxBidirectionalStreamLocalData = FlowControlGlobals.initialReceiveSpace
        }

        initialMaxBidirectionalStreamRemoteData = FlowControlGlobals.initialReceiveSpace
        initialMaxUnidirectionalStreamData = FlowControlGlobals.initialReceiveSpace
    }
}

#endif
