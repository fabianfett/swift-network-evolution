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

#if !NETWORK_NO_SWIFT_QUIC

import XCTest

#if canImport(SwiftNetwork)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork
#elseif canImport(Network)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import Network
#endif

#if canImport(SwiftNetworkTestHarness)
@_spi(TestHarness) @_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetworkTestHarness
#endif

@available(Network 0.1.0, *)
let quicStreamTestsLogPrefixer = LogPrefixer("[QUICStreamTests]")

@available(Network 0.1.0, *)
final class QUICStreamTests: XCTestCase {
    var stream: QUICStreamInstance!
    var connection = QUICConnection(context: NetworkContext.implicitContext)

    override func setUp() {
        stream = QUICStreamInstance(parent: connection, inbound: false)
        stream.setup(
            streamID: QUICStreamID(0),
            logPrefixer: quicStreamTestsLogPrefixer
        )
    }

    override func tearDown() {
        // The stream and the connection were both built outside a protocol stack, so nothing
        // else hands their event states back. The stream's `deinit` is an external entry point
        // that acquires the event context, so release it on the queue too.
        connection.context.onQueue {
            self.stream.destroyFromExternalTest()
            self.stream = nil
            self.connection.destroyFromExternalTest()
        }
    }

    // MARK: - Sentinel-backed computed properties (inboundApplicationError,
    // outboundApplicationError, streamID)

    func testStreamIDDefaultsToNilBeforeSetup() {
        connection.context.onQueue {
            let freshStream = QUICStreamInstance(parent: self.connection, inbound: false)
            XCTAssertNil(freshStream.streamID)
            freshStream.destroyFromExternalTest()
        }
    }

    func testInboundApplicationErrorDefaultsToNil() {
        XCTAssertNil(stream.inboundApplicationError)
    }

    func testOutboundApplicationErrorDefaultsToNil() {
        XCTAssertNil(stream.outboundApplicationError)
    }

    func testInboundApplicationErrorRoundTrip() {
        stream.inboundApplicationError = 42
        XCTAssertEqual(stream.inboundApplicationError, 42)
        stream.inboundApplicationError = nil
        XCTAssertNil(stream.inboundApplicationError)
    }

    func testInboundApplicationErrorZeroIsNotConfusedWithNil() {
        stream.inboundApplicationError = 0
        XCTAssertNotNil(stream.inboundApplicationError)
        XCTAssertEqual(stream.inboundApplicationError, 0)
    }

    func testOutboundApplicationErrorRoundTrip() {
        stream.outboundApplicationError = 99
        XCTAssertEqual(stream.outboundApplicationError, 99)
        stream.outboundApplicationError = nil
        XCTAssertNil(stream.outboundApplicationError)
    }

    func testOutboundApplicationErrorZeroIsNotConfusedWithNil() {
        stream.outboundApplicationError = 0
        XCTAssertNotNil(stream.outboundApplicationError)
        XCTAssertEqual(stream.outboundApplicationError, 0)
    }

    func testResetStreamIDUpdatesStreamID() {
        let newStreamID = QUICStreamID(UInt32(4))
        stream.resetStreamID(streamID: newStreamID)
        XCTAssertEqual(stream.streamID, newStreamID)
        XCTAssertEqual(stream.streamID?.value, 4)
    }
    func testApplicationErrorMaxIsReservedAsSentinel() {
        stream.inboundApplicationError = UInt64.max
        XCTAssertNil(stream.inboundApplicationError)
    }
}

@available(Network 0.1.0, *)
final class QUICStreamIDStateTests: XCTestCase {
    var streamsState = QUICStreamIDState(.unidirectional)
    var connection = QUICConnection(context: NetworkContext.implicitContext)
    var stream: QUICStreamInstance!
    var logPrefix = LogPrefixer("[QUICStreamTests]")

    override func setUp() {
        stream = QUICStreamInstance(parent: connection, inbound: false)
        stream.setup(
            streamID: QUICStreamID(0),
            logPrefixer: quicStreamTestsLogPrefixer
        )
    }

    override func tearDown() {
        streamsState.removeAllPending()
        // The stream and the connection were both built outside a protocol stack, so nothing
        // else hands their event states back. The stream's `deinit` is an external entry point
        // that acquires the event context, so release it on the queue too.
        connection.context.onQueue {
            self.stream.destroyFromExternalTest()
            self.stream = nil
            self.connection.destroyFromExternalTest()
        }
    }

    func testPendingStartStreams() {
        XCTAssertEqual(streamsState.pendingStartStreams.count, 0)
        XCTAssertNil(streamsState.pendingStartStreams.first)

        XCTAssertFalse(stream.pendingStart)
        streamsState.addPending(stream)
        XCTAssertTrue(stream.pendingStart)
        XCTAssertEqual(streamsState.pendingStartStreams.count, 1)
        XCTAssertEqual(streamsState.pendingStartStreams.first?.streamID, stream.streamID)

        streamsState.removePending(stream)
        XCTAssertFalse(stream.pendingStart)
        XCTAssertEqual(streamsState.pendingStartStreams.count, 0)
        XCTAssertNil(streamsState.pendingStartStreams.first)
    }
}

#endif
