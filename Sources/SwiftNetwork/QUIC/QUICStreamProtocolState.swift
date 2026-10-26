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

/// The protocol state of one QUIC stream: send and receive states, error codes, and flags.
@available(Network 0.1.0, *)
struct QUICStreamProtocolState: ~Copyable {
    // Field ordering is important because it makes sure we are not taking extra hits for padding:
    // the small fields go after the 8 byte ones, so the stream instance stays within a 256 byte
    // allocation.

    // Using optional values here throws the padding off so use .max and vend back optional values
    private var inboundApplicationErrorStorage: UInt64 = .max
    private var outboundApplicationErrorStorage: UInt64 = .max
    // QUICStreamID.maxValid is 2^62-1 and will reject anything above it so we use this to denote nil
    private var streamIDStorage: UInt64 = .max

    var send = QUICSendState()

    struct Flags: OptionSet {
        init(rawValue: Self.RawValue) {
            self.rawValue = rawValue
        }
        var rawValue: UInt32
        static let pendingStart = Flags(rawValue: 1 << 0)  // on the pending list
        static let closed = Flags(rawValue: 1 << 1)  // stream is closed by handle_stop or report_done
        static let writeClosed = Flags(rawValue: 1 << 2)
        static let readClosed = Flags(rawValue: 1 << 3)
        static let receivedStopSending = Flags(rawValue: 1 << 4)
        static let unidirectional = Flags(rawValue: 1 << 5)
        static let resetReceived = Flags(rawValue: 1 << 6)
        static let peerAcknowledgedFIN = Flags(rawValue: 1 << 7)
        static let markedInboundFINOnFrame = Flags(rawValue: 1 << 8)
        static let applicationMarkedIdle = Flags(rawValue: 1 << 9)
        /// `QUICConnectionCore` is done with both directions of the stream.
        static let coreStreamClosed = Flags(rawValue: 1 << 10)
    }
    var flags = Flags()

    var receive = QUICReceiveState()

    init() {}

    /// The application error code for the inbound (receive) direction.
    ///
    /// Used for the `STOP_SENDING` frame.
    @inline(always)
    var inboundApplicationError: UInt64? {
        get { inboundApplicationErrorStorage == .max ? nil : inboundApplicationErrorStorage }
        set { inboundApplicationErrorStorage = newValue ?? .max }
    }
    /// The application error code for the outbound (send) direction.
    ///
    /// Used for the `RESET_STREAM` frame.
    @inline(always)
    var outboundApplicationError: UInt64? {
        get { outboundApplicationErrorStorage == .max ? nil : outboundApplicationErrorStorage }
        set { outboundApplicationErrorStorage = newValue ?? .max }
    }
    @inline(always)
    var streamID: QUICStreamID? {
        get { streamIDStorage == .max ? nil : QUICStreamID(streamIDStorage)! }
        set { streamIDStorage = newValue?.value ?? .max }
    }
}

#endif
