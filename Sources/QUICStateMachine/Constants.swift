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
//  Constants for QUIC

#if !NETWORK_NO_SWIFT_QUIC
@available(Network 0.1.0, *)
package enum Constants {
    package static let initialMSS = 1200
    package static let streamIDDatagramMask: UInt64 = 0x8000_0000_0000_0000
    package static let pathIdentifierTypeThisPath: UInt64 = 2
    package static let highMemorySystem: UInt64 = 3 * 1024 * 1024 * 1024
    package static let maxQueuedPackets: Int = 5
    package static let maxStreamLimit: UInt64 = (UInt64.max >> 4) + 1  // UINT60_MAX
    package static let minimumPayloadLength = 3
    package static let activeCIDLimit: UInt64 = 64
    package static let maxDatagramFrameSize = 65535
    package static let minimumPacketSize = 21
    package static let maximumAllowedAckDelay = UInt32.max

    // Check burst every 10 packets
    package static let packetBurstCount = 10

    // Don't burst more than 40 packets at a time
    package static let maxPacketBurstCount = 40

    // Don't burst for more than 1 millisecond at a time
    package static let maxPacketBurstDuration = NetworkDuration.milliseconds(1)

    package static let packetReorderThreshold = PacketNumber(3)
    package static let timeReorderThreshold = 3
    package static let persistentCongestionThreshold = 3
    package static let maxPacketReorderThreshold = 20
    package static let adaptiveTimeThreshold = true
    package static let adaptivePacketThreshold = true
    package static let defaultKeepaliveValue = UInt16.max
    package static let defaultKeepaliveDuration: NetworkDuration = .seconds(20)
    package static let defaultVersion: QUICVersion = .v1
    package static let retryTokenMaxLength: UInt8 = 128
    package static let retryTokenIntegrityTagLength: UInt8 = 16
    package static let statelessResetTokenSize: Int = 16
    package static let preferredAddressCIDSequenceNumber: UInt64 = 1
    package static let defaultIdleTimeout: NetworkDuration = .seconds(30)
    package static let defaultMaxConnectionIDs = 8
    // Don't delay more than 10ms between two bursts
    package static let maxBurstIntervalKernelPacing: NetworkDuration = .milliseconds(10)
    // The congestion window will have to be reset after a non-validated period.
    package static let congestionWindowNonvalidatedPeriod: NetworkDuration = .minutes(3)
    package static let streamDataMaxSize = UInt32.max
}

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public enum QUICVersion: UInt32, Sendable {
    case negotiation = 0
    case v1 = 0x0000_0001
    // Versions that follow the pattern 0x?a?a?a?a are reserved for forcing
    // version negotiation to be exercised -- that is, any version number where the
    // low four bits of all bytes is 1010 (in binary). A client or server MAY advertise
    // support for any of these reserved versions.
    case negotiationPattern = 0x1a2a_3a4a

    package static let versionHeaderSize = MemoryLayout<UInt32>.size
    // Version used for unit testing
    package static let unsupportedVersion: UInt32 = 0x0102_0304
}
#endif

/// ACK delay limits from RFC 9000, shared by transport parameters and ACK processing.
@available(Network 0.1.0, *)
package enum AckDefaults {
    package static let defaultDelayExponent = 3 /* 2 ** 3 */
    package static let defaultMaxDelay: NetworkDuration = .milliseconds(25)
    package static let maxDelayExponent = 20  // Values above 20 are invalid
    /// The largest valid max_ack_delay: values of 2^14 ms or greater are invalid (RFC 9000
    /// Section 18.2).
    package static let maxDelay: NetworkDuration = .milliseconds((1 << 14) - 1)
}
