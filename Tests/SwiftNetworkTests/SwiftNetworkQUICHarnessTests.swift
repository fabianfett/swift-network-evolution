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

import Synchronization
import XCTest

#if !targetEnvironment(simulator) && (os(iOS) || os(macOS) || os(Linux) || os(Android))

#if canImport(SwiftNetwork)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork
#elseif canImport(Network)
@_spi(Essentials) @_spi(ProtocolProvider) import Network
#endif

#if canImport(SwiftNetworkTestHarness)
@_spi(TestHarness) @_spi(Essentials) @_spi(ProtocolProvider) import SwiftNetworkTestHarness
#endif

#if IMPORT_SWIFTTLS
#if EXPORT_SWIFTTLS
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#else
@_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) @_weakLinked internal import SwiftTLS
#endif
#endif

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
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

#if canImport(Dispatch)
import Dispatch
#endif

#if IMPORT_SWIFTTLS
#if canImport(SwiftTLS)
@available(Network 0.1.0, *)
final class SwiftNetworkQUICHarnessTests: NetTestCase {

    // MARK: Handshake tests

    func testQUICHandshake() {
        QUICTestHarness().runQUICTest()
    }

    #if canImport(Dispatch)
    func testQUICHandshakeConcurrent() {
        let context = NetworkContext(identifier: "concurrent")
        let queue = DispatchQueue(label: "concurrent queue", attributes: .concurrent)
        let group = DispatchGroup()
        for i in 0..<20 {
            group.enter()
            queue.async {
                QUICTestHarness(context: context).runQUICTest(identifier: "Concurrent\(i)")
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: DispatchTime.now() + .seconds(5)), .success)
    }
    #endif

    func testQUICHandshakeWithGiantALPNList() {
        var alpnList = ["network_test"]
        for i in 0..<100 {
            alpnList.append("network_test_\(i)")
        }

        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.applicationProtocols = alpnList
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        QUICTestHarness().runQUICTest(clientOptions: clientOptions)
    }

    func testQUICHandshakeWithBadALPNList() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.applicationProtocols = ["bad_alpn"]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        QUICTestHarness().runQUICTest(
            expectHandshakeError: .init(quicTransportError: QUICTransportError(Int64(0x0100), "TLS error")!),
            timeout: 10.0,
            clientOptions: clientOptions
        )
    }

    // A server that advertises more than 2^60 initial bidirectional streams violates the
    // transport parameter limits, so the client closes from `reportReady` when TLS reports the
    // handshake as connected. Here that happens while the client is processing the server's
    // flight, so the close is deferred until the packet has been handled.
    func testQUICHandshakeWithInvalidServerTransportParameters() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = Constants.maxStreamLimit + 1 }

        QUICTestHarness().runQUICTest(
            expectHandshakeError: .init(
                quicTransportError: QUICTransportError(.transportParameterError, "initial FC over limit")
            ),
            serverOptions: serverOptions
        )
    }

    #if EXPORT_SWIFTTLS
    // The same invalid transport parameters, but the client verifies the server asynchronously.
    // TLS then completes the handshake from its own async continuation rather than from inside
    // the client's packet processing, so `reportReady`, and the close it raises, runs while crypto
    // is still handling the connected event from TLS.
    func testQUICHandshakeWithInvalidServerTransportParametersAfterAsyncVerification() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = Constants.maxStreamLimit + 1 }

        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.asyncVerifier = AsyncVerifier(availableCertificateTypes: [.rawPublicKey]) { info in
            guard let deliverResult = info.deliverResult else {
                return .invalid(reason: "No way to deliver an async result")
            }
            // Deliver from off the context, as a real verifier would; the TLS instance has to
            // hop back onto the context itself.
            DispatchQueue.global().async {
                deliverResult(.valid)
            }
            return .waiting
        }
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        QUICTestHarness().runQUICTest(
            expectHandshakeError: .init(
                quicTransportError: QUICTransportError(.transportParameterError, "initial FC over limit")
            ),
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    // A client whose verifier accepts the server from off the context, after a while: the
    // handshake waits for the result, then completes and carries data.
    func testQUICHandshakeWithAsyncVerification() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.asyncVerifier = AsyncVerifier(availableCertificateTypes: [.rawPublicKey]) { info in
            guard let deliverResult = info.deliverResult else {
                return .invalid(reason: "No way to deliver an async result")
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(20)) {
                deliverResult(.valid)
            }
            return .waiting
        }
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        QUICTestHarness().runQUICTest(dataBlock: Array("Hello World!".utf8), clientOptions: clientOptions)
    }
    #endif

    #if EXPORT_SWIFTTLS
    func testQUICHandshakeForceAES128() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.supportedCipherSuites = [.AES128GCM_SHA256]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        let serverOptions = QUICProtocol.options()
        var serverTLSOptions = serverOptions.tlsOptions
        serverTLSOptions.tlsOptions.supportedCipherSuites = [.AES128GCM_SHA256]
        serverOptions.modifyTLSOptions { $0 = serverTLSOptions }

        QUICTestHarness().runQUICTest(
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    func testQUICHandshakeForceAES256() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.supportedCipherSuites = [.AES256GCM_SHA384]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        let serverOptions = QUICProtocol.options()
        var serverTLSOptions = serverOptions.tlsOptions
        serverTLSOptions.tlsOptions.supportedCipherSuites = [.AES256GCM_SHA384]
        serverOptions.modifyTLSOptions { $0 = serverTLSOptions }

        QUICTestHarness().runQUICTest(
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    func testQUICHandshakeForceChaCha() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.supportedCipherSuites = [.chacha20Poly1305_SHA256]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        let serverOptions = QUICProtocol.options()
        var serverTLSOptions = serverOptions.tlsOptions
        serverTLSOptions.tlsOptions.supportedCipherSuites = [.chacha20Poly1305_SHA256]
        serverOptions.modifyTLSOptions { $0 = serverTLSOptions }

        QUICTestHarness().runQUICTest(
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    func testQUICHandshakeNegotiateChaCha() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.supportedCipherSuites = [.chacha20Poly1305_SHA256]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        let serverOptions = QUICProtocol.options()
        var serverTLSOptions = serverOptions.tlsOptions
        serverTLSOptions.tlsOptions.supportedCipherSuites = [.AES256GCM_SHA384, .chacha20Poly1305_SHA256]
        serverOptions.modifyTLSOptions { $0 = serverTLSOptions }

        QUICTestHarness().runQUICTest(
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    func testQUICHandshakeCiphersuiteMismatch() {
        let clientOptions = QUICProtocol.options()
        var tlsOptions = clientOptions.tlsOptions
        tlsOptions.tlsOptions.supportedCipherSuites = [.chacha20Poly1305_SHA256]
        clientOptions.modifyTLSOptions { $0 = tlsOptions }

        let serverOptions = QUICProtocol.options()
        var serverTLSOptions = serverOptions.tlsOptions
        serverTLSOptions.tlsOptions.supportedCipherSuites = [.AES256GCM_SHA384]
        serverOptions.modifyTLSOptions { $0 = serverTLSOptions }

        QUICTestHarness().runQUICTest(
            expectHandshakeError: .init(quicTransportError: QUICTransportError(Int64(0x0100), "TLS error")!),
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }
    #endif

    func testQUICHandshakeWithSCIDLength() {
        let clientOptions = QUICProtocol.options()
        clientOptions.modifyConnectionOptions { $0.sourceConnectionIDLength = 10 }
        QUICTestHarness().runQUICTest(clientOptions: clientOptions)
    }

    func testQUICHandshakeWithInitialServerSCID() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialSourceConnectionID = QUICConnectionID(10) }
        serverOptions.modifyConnectionOptions { $0.initialStatelessResetToken = QUICStatelessResetToken() }
        QUICTestHarness().runQUICTest(serverOptions: serverOptions)
    }

    func testQUICHandshakeWithManualServerCIDs() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialSourceConnectionID = QUICConnectionID(10) }
        serverOptions.modifyConnectionOptions { $0.initialStatelessResetToken = QUICStatelessResetToken() }
        serverOptions.modifyConnectionOptions { $0.disableAutomaticNewConnectionIDs = true }
        QUICTestHarness().runQUICTest(
            serverOptions: serverOptions,
            extraServerCIDs: [
                (QUICConnectionID(10), QUICStatelessResetToken()),
                (QUICConnectionID(10), QUICStatelessResetToken()),
                (QUICConnectionID(10), QUICStatelessResetToken()),
            ]
        )
    }

    func testQUICHandshakeWithDelay() {
        QUICTestHarness().runQUICTest(
            clientLinkDelay: .milliseconds(50),
            serverLinkDelay: .milliseconds(50)
        )
    }

    // MARK: Data transfer tests

    func testQUICEchoHelloWorld() {
        QUICTestHarness().runQUICTest(dataBlock: Array("Hello World!".utf8))
    }

    func testQUICEchoHelloWorldMultistream() {
        QUICTestHarness().runQUICTest(
            streamCount: 4,
            dataBlock: Array("Hello World!".utf8)
        )
    }

    func testQUICEchoHelloWorldMarkIdle() {
        QUICTestHarness().runQUICTest(
            dataBlock: Array("Hello World!".utf8),
            shouldMarkIdle: true
        )
    }

    func testQUICEchoHelloWorldMultistreamMarkIdle() {
        QUICTestHarness().runQUICTest(
            streamCount: 4,
            dataBlock: Array("Hello World!".utf8),
            shouldMarkIdle: true
        )
    }

    func testQUICEchoHelloWorldMultistreamWithMaxStreamsIncreasing() {
        // In this test the client should start with an initial max of 8 bidirectional streams.
        // We are telling the client to open 16 bidirectional streams and so the server should
        // detect that the client is about to hit the remote stream limit and provide a MAX_STREAMS
        // update to 16 streams so the client should be able finish opening all 16 streams.
        QUICTestHarness().runQUICTest(
            streamCount: 16,
            dataBlock: Array("Hello World!".utf8),
            sendMaxStreamUpdate: true
        )
    }

    func testQUICEchoHelloWorldMultistreamWithPendingStreams() {
        // In this test the client should start with an initial max streams of 8.
        // The client will open 8 streams and then open 1 more stream and have it go into pending because the client has reached its local max.
        // Send a MAX_STREAMS frame from the server to raise the client's stream limit and start the pending stream.
        // The pending stream should then go into ready and send / receive data.
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = 8 }
        QUICTestHarness().runQUICServerTestForPendingBidirectional(
            dataBlock: Array("Hello World!".utf8),
            serverOptions: serverOptions
        )
    }

    func testQUIC50BidirectionalStreams() {
        // Server advertises that the client can open 50 bidirectional streams
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = 50 }
        QUICTestHarness().runQUICTest(
            streamCount: 50,
            dataBlock: Array("Hello World!".utf8),
            serverOptions: serverOptions
        )
    }

    func testQUIC1000BidirectionalStreamsEcho1k() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = 1000 }
        QUICTestHarness().runQUICTest(
            streamCount: 1000,
            blockSize: 1000,
            blockCount: 1,
            serverOptions: serverOptions
        )
    }

    func testQUICConnectionCloseError() {
        QUICTestHarness().runQUICTest(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            applicationError: 10,  // PROTOCOL_VIOLATION
            applicationErrorReason: "QUIC Error thrown from test"
        )
    }

    func testQUICApplicationCloseError() {
        QUICTestHarness().runQUICTest(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            applicationError: 102,  // Application specific error code (Not a code from ConnectionCloseError)
            applicationErrorReason: "Application error reason to test",
            sendApplicationCloseError: true
        )
    }

    func testQUICApplicationCloseErrorWithOverlappingCode() {
        QUICTestHarness().runQUICTest(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            // Application specific error code (SHOULD *NOT* map to a code from ConnectionCloseError)
            applicationError: 8,
            applicationErrorReason: "Application error reason to test",
            sendApplicationCloseError: true
        )
    }

    func testQUICStreamResetError() {
        QUICTestHarness().runQUICTest(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            sendFIN: false,  // Don't send a FIN, to allow the stream to reset
            applicationError: 10,  // Application error code
            sendStreamResetError: true
        )
    }

    func testQUICStreamStopSendingError() {
        QUICTestHarness().runQUICTest(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            sendFIN: false,  // Don't send a FIN, to allow the stream to have stop-sending
            applicationError: 102,  // Application error code
            sendStreamStopSendingError: true
        )
    }

    func testQUICNewStreamRaceWithResetStream() {
        QUICTestHarness().runQUICNewStreamWithImmediateAbort(abortKind: .reset)
    }

    func testQUICNewStreamRaceWithStopSending() {
        QUICTestHarness().runQUICNewStreamWithImmediateAbort(abortKind: .stopSending)
    }

    func testQUICResetStreamFirstFrameOnNewStream() {
        QUICTestHarness().runQUICResetStreamFirstFrameOnNewStream()
    }

    func testQUICEmptyFinCleanCloseSendsFinNotReset() {
        QUICTestHarness().runEmptyFinCleanCloseSendsFinNotReset()
    }

    func testQUICResetStreamDoesNotAffectOppositeDirection() {
        QUICTestHarness().runQUICTest(
            streamCount: 1,
            dataBlock: Array("Hello World!".utf8),
            sendFIN: false,
            applicationError: 42,
            sendStreamResetError: true,
            verifyResetStreamHalfClosure: true
        )
    }

    // MARK: Flow control credit for unread inbound bytes

    // Inbound bytes that the application never reads still consumed
    // connection-level flow control credit. Dropping the stream must return that
    // credit, or the connection-level receive window is permanently consumed and
    // the peer eventually cannot send at all.
    func testQUICDropUnreadInboundBytesReturnsFlowControlCredit() {
        QUICTestHarness().runQUICDropUnreadInboundBytesLoop()
    }

    // Control for the test above: the same loop, but the application drains the
    // bytes before aborting. Credit is returned through the normal read path, so
    // this must not stall. If both tests fail, the cause is not credit accounting.
    func testQUICReadInboundBytesBeforeAbortReturnsFlowControlCredit() {
        QUICTestHarness().runQUICDropUnreadInboundBytesLoop(readBeforeAbort: true)
    }

    // A single large drop, bigger than the whole advertised window, must also be
    // credited back rather than leaving the peer permanently blocked.
    func testQUICDropLargeUnreadInboundBlockReturnsFlowControlCredit() {
        QUICTestHarness().runQUICDropUnreadInboundBytesLoop(
            rounds: 6,
            chunkSize: 10_000,
            initialMaxData: 20_000
        )
    }

    // MARK: Closing a stream from inside ACK processing

    // Closing a stream with `stop()` sends a RESET_STREAM. Processing the peer's
    // ACK for it closes the stream, which sends again — re-entering the
    // connection while it handles the ACK.
    func testQUICStopStreamWithUnreadBytesSurvivesResetAck() {
        QUICTestHarness().runQUICStopStreamAfterPeerWrite()
    }

    // The same close path, with the inbound bytes drained first: the re-entry does
    // not depend on there being unread data.
    func testQUICStopStreamAfterReadingSurvivesResetAck() {
        QUICTestHarness().runQUICStopStreamAfterPeerWrite(readBeforeStop: true)
    }

    func testQUICEcho40KiB() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4)
    }

    func testQUICEcho40KiBBatched() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, shouldBatchSends: true)
    }

    func testQUICEcho40KiBSmallReads() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, clientReadChunkSize: 1000)
    }

    func testQUICEcho40KiBWithDelay() {
        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            clientLinkDelay: .milliseconds(50),
            serverLinkDelay: .milliseconds(50)
        )
    }

    func testQUICEcho40KiBNoPMTUD() {
        let clientOptions = QUICProtocol.options()
        clientOptions.modifyConnectionOptions { $0.pmtud = false }

        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.pmtud = false }

        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            clientOptions: clientOptions,
            serverOptions: serverOptions
        )
    }

    func testQUICEcho40KiBRaisesTheMSSWithPMTUD() {
        // Probes as soon as the handshake is confirmed, rather than once enough data waits.
        let clientOptions = QUICProtocol.options()
        clientOptions.connectionOptions.pmtudIgnoreCost = true
        let serverOptions = QUICProtocol.options()
        serverOptions.connectionOptions.pmtudIgnoreCost = true

        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            clientOptions: clientOptions,
            serverOptions: serverOptions,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Check the MSS")
                harness.context.async {
                    let instances = [harness.state?.clientInstance, harness.state?.serverInstance]
                    for (instance, side) in zip(instances, ["client", "server"]) {
                        guard let instance, let box = instance.coreBox, let path = instance.currentPath else {
                            XCTFail("No \(side) core")
                            continue
                        }
                        // The 1500-byte link carries more than the initial 1200 bytes.
                        XCTAssertGreaterThan(box.core.maxDatagramSize, Constants.initialMSS, side)
                        XCTAssertEqual(path.mss, box.core.maxDatagramSize, side)
                    }
                    expectation.fulfill()
                }
                XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
            }
        )
    }

    func testQUICEcho40KiBWithL4S() {
        let clientOptions = QUICProtocol.options()
        clientOptions.connectionOptions.enableL4S = true
        let serverOptions = QUICProtocol.options()
        serverOptions.connectionOptions.enableL4S = true

        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            clientOptions: clientOptions,
            serverOptions: serverOptions,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Check the congestion controller")
                harness.context.async {
                    let instances = [harness.state?.clientInstance, harness.state?.serverInstance]
                    for (instance, side) in zip(instances, ["client", "server"]) {
                        guard let instance, let box = instance.coreBox else {
                            XCTFail("No \(side) core")
                            continue
                        }
                        // L4S is Prague, paced, in ECT(1) packets.
                        XCTAssertEqual(box.core.recovery.controller.algorithm, .prague, side)
                        XCTAssertNotNil(box.core.recovery.pacer, side)
                        XCTAssertTrue(box.core.configuration.useECT1, side)
                    }
                    expectation.fulfill()
                }
                XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
            }
        )
    }

    func testQUICEcho40KiBMultistream() {
        QUICTestHarness().runQUICTest(streamCount: 4, blockSize: 10240, blockCount: 4)
    }

    func testQUICEcho40KiBMultistreamWithMetrics() {
        QUICTestHarness().runQUICTest(
            streamCount: 8,
            blockSize: 10240,
            blockCount: 8,
            validateMetrics: true
        )
    }

    func testQUIC13AutomaticStreams() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = 5 }
        serverOptions.modifyConnectionOptions { $0.maximumConcurrentBidirectionalStreams = 5 }
        QUICTestHarness().runQUICTest(
            streamCount: 13,
            blockSize: 10240,
            blockCount: 4,
            serverOptions: serverOptions
        )
    }

    func testQUIC100AutomaticStreams() {
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsBidirectional = 8 }
        serverOptions.modifyConnectionOptions { $0.maximumConcurrentBidirectionalStreams = 8 }
        QUICTestHarness().runQUICTest(
            streamCount: 100,
            blockSize: 10240,
            blockCount: 4,
            serverOptions: serverOptions
        )
    }

    func testQUICEcho100KiB() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 10)
    }

    // Many small writes: the send buffer resumes sending in the middle of one
    func testQUICEcho300KiB() {
        QUICTestHarness().runQUICTest(blockSize: 300, blockCount: 1000)
    }

    // 1MiB == 1,048,576, this is 1,024,000
    func testQUICEcho1MiB() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 100)
    }

    // ACKs should be bundled on outgoing STREAM frames rather than going out in their own
    // packet as much as possible, this test tracks that.
    func testQUICEcho1MiBAckBundling() {
        let observedPacketSizes = Mutex<[Int]>([])
        let observeFrameHandler: BridgeObserveFrameHandler = { firstByte, byteCount in
            // Identify short header packet to accumulate the total sizes at the end
            guard (firstByte & 0xC0) == 0x40 else { return }
            observedPacketSizes.withLock { $0.append(byteCount) }
        }

        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 100,
            bridgeObserveFrameHandler: observeFrameHandler
        )

        let packetSizes = observedPacketSizes.withLock { $0 }
        XCTAssertFalse(packetSizes.isEmpty, "packetSizes should not be empty")

        // A standalone ACK (no STREAM data) fits comfortably under 100 bytes, but a
        // packet carrying STREAM data is padded out much closer to the path's MTU.
        let ackOnlySizeThreshold = 100
        let ackOnlyPacketCount = packetSizes.filter { $0 < ackOnlySizeThreshold }.count
        print("ackOnlyPacketCount: \(ackOnlyPacketCount), packetSizes: \(packetSizes.count)")
        XCTAssertLessThan(
            ackOnlyPacketCount,
            10,  // Use 10 as an arbitrary threshold here
            "Most packets should bundle an ACK with STREAM data rather than going out alone"
        )
    }

    #if !NETWORK_PRIVATE
    // Note: These tests takes too long to in for automation
    // Changed to 30 seconds to give it leeway to run locally
    // This passes "swift test" built default, ie. non-release, after ~9sec
    // Built release "swift test -c release" it passes in ~0.15sec
    func testQUICEcho10MiB() {
        // This is big enough to hit MAX_STREAM_DATA limits/Congestion
        QUICTestHarness().runQUICTest(blockSize: 10_240, blockCount: 1024, timeout: 30.0)
    }

    #if !DEBUG
    // These tests are big enough to hit MAX_DATA limits/Congestion

    // Built release "swift test -c release" it passes in ~0.3sec
    func testQUICEcho20MiB() throws {
        try XCTSkipIf(true)
        QUICTestHarness().runQUICTest(blockSize: 10_240, blockCount: 2 * 1024, timeout: 1000.0)
    }

    // Built release "swift test -c release" it passes in ~1.5sec
    func testQUICEcho100MiB() throws {
        try XCTSkipIf(true)
        QUICTestHarness().runQUICTest(blockSize: 10_240, blockCount: 10_240, timeout: 2000.0)
    }

    // Built release "swift test -c release" it passes in ~15sec
    func testQUICEcho1GiB() throws {
        try XCTSkipIf(true)
        QUICTestHarness().runQUICTest(blockSize: 10_240, blockCount: 100 * 1_024, timeout: 20000.0)
    }
    #endif
    #endif

    // MARK: Loss tests

    func testQUICDrop1ClientPacket() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, clientDrops: .init(10))
    }

    func testQUICDrop1ServerPacket() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, serverDrops: .init(10))
    }

    func testQUICDrop2ClientPackets() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, clientDrops: .init(20...21))
    }

    func testQUICDrop2ServerPackets() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, serverDrops: .init(20...21))
    }

    func testQUICDrop10ClientPackets() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, clientDrops: .init(20...29))
    }

    func testQUICDrop10ServerPackets() {
        QUICTestHarness().runQUICTest(blockSize: 10240, blockCount: 4, serverDrops: .init(20...29))
    }

    func testQUICDropClientInitial() {
        QUICTestHarness().runQUICTest(blockSize: 1000, blockCount: 4, clientDrops: .init(0))
    }

    func testQUICDropServerInitial() {
        QUICTestHarness().runQUICTest(blockSize: 1000, blockCount: 4, serverDrops: .init(0))
    }

    func testQUICDropBothInitials() {
        QUICTestHarness().runQUICTest(
            blockSize: 5000,
            blockCount: 1,
            clientDrops: .init([0...1, 6...6]),
            serverDrops: .init([0...0])
        )
    }

    func testQUICDropServerHandshake() {
        QUICTestHarness().runQUICTest(blockSize: 1000, blockCount: 4, serverDrops: .init(1))
    }

    func testQUICDropServerInitialAndHandshake() {
        QUICTestHarness().runQUICTest(blockSize: 1000, blockCount: 4, serverDrops: .init([0...0, 3...3]))
    }

    func testQUICDropScenario1() {
        QUICTestHarness().runQUICTest(
            blockSize: 5000,
            blockCount: 1,
            clientDrops: .init([0...1]),
            serverDrops: .init([0...0, 2...3]),
            timeout: 10
        )
    }

    func testQUICDropScenario2() {
        QUICTestHarness().runQUICTest(
            blockSize: 5000,
            blockCount: 1,
            clientDrops: .init([3...3, 6...6]),
            serverDrops: .init([0...0, 2...2, 6...6]),
            timeout: 10
        )
    }

    func testQUICDropScenario3() {
        QUICTestHarness().runQUICTest(
            blockSize: 5000,
            blockCount: 1,
            clientLinkDelay: .milliseconds(10),
            serverLinkDelay: .milliseconds(10),
            clientDrops: .init([1...7]),
            serverDrops: .init([1...9]),
            timeout: 15
        )
    }

    #if !os(Linux)
    func testQUICSevereDrops() throws {
        // Induce severe drops (100 in each direction) to heavily exercise recovery
        // The patterns of drops were generated randomly, but shown to hit pathological cases.
        // They are statically included here to ensure that behavior is hit consistently.
        let streamCount = 4
        let blockSize = 10240
        let blockCount = 100
        let clientDrops = DatagramDrops([
            35...39, 185...189,
            357...361, 413...417,
            446...450, 843...847,
            1002...1006, 1458...1462,
            1537...1541, 1578...1582,
            1858...1862, 1986...1990,
            2041...2045, 2205...2209,
            2236...2240, 2252...2256,
            2297...2301, 2446...2450,
            2855...2859, 2893...2897,
            2950...2954, 2953...2957,
            2955...2959, 3121...3125,
            3478...3482, 3567...3571,
            3584...3588, 3704...3708,
            3892...3896, 3912...3916,
        ])
        let serverDrops = DatagramDrops([
            90...94, 137...141,
            295...299, 536...540,
            738...742, 953...957,
            1143...1147, 1314...1318,
            1462...1466, 1536...1540,
            1539...1543, 1617...1621,
            1716...1720, 1841...1845,
            1912...1916, 1970...1974,
            2076...2080, 2393...2397,
            2573...2577, 2900...2904,
            3001...3005, 3099...3103,
            3165...3169, 3213...3217,
            3310...3314, 3311...3315,
            3367...3371, 3522...3526,
            3563...3567, 3594...3598,
        ])

        QUICTestHarness().runQUICTest(
            streamCount: streamCount,
            blockSize: blockSize,
            blockCount: blockCount,
            clientDrops: clientDrops,
            serverDrops: serverDrops,
            timeout: 20
        )
    }
    #endif

    func testQUICBlockClientPacketGeneration() {
        var clientDrops = DatagramDrops(10)
        clientDrops.blockPacketGeneration = true
        QUICTestHarness().runQUICTest(blockSize: 500000, blockCount: 1, clientDrops: clientDrops)
    }

    // MARK: Datagram tests

    func testQUICDatagramHelloWorld() {
        QUICTestHarness().runQUICTest(datagram: true, dataBlock: Array("Hello World!".utf8))
    }

    func testQUICDatagram1() {
        QUICTestHarness().runQUICTest(datagram: true, blockSize: 1000, blockCount: 1)
    }

    func testQUICDatagram10() {
        QUICTestHarness().runQUICTest(datagram: true, blockSize: 1000, blockCount: 10)
    }

    func testQUICDatagram10Batched() {
        // The batch is flushed at once, and two of these datagrams don't fit in one packet, so the
        // rest have to wait for the next packets rather than being dropped
        QUICTestHarness().runQUICTest(
            datagram: true,
            blockSize: 1000,
            blockCount: 10,
            shouldBatchSends: true
        )
    }

    func testQUICDatagramWithLargeInitialPacketSize() {
        let clientOptions = QUICProtocol.options()
        clientOptions.modifyConnectionOptions { $0.initialPacketSize = 1400 }

        let observedInitialPacketSizes = Mutex<[Int]>([])
        let observeFrameHandler: BridgeObserveFrameHandler = { firstByte, byteCount in
            // Verify initial packet
            guard (firstByte & 0xF0) == 0xC0 else { return }
            observedInitialPacketSizes.withLock { $0.append(byteCount) }
        }

        QUICTestHarness().runQUICTest(
            datagram: true,
            blockSize: 1000,
            blockCount: 10,
            clientOptions: clientOptions,
            bridgeObserveFrameHandler: observeFrameHandler
        )

        XCTAssertFalse(
            observedInitialPacketSizes.withLock { $0.isEmpty },
            "Should have observed at least one Initial packet"
        )
        XCTAssertEqual(observedInitialPacketSizes.withLock { $0.first }, 1400)
    }

    func testQUICDatagramRemoteMaxDatagramFrameSize() {
        QUICTestHarness().runQUICTest(
            datagram: true,
            blockSize: 1000,
            blockCount: 1,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait for remote datagram frame size to be fetched")
                harness.context.async {
                    let clientMetadata: ProtocolMetadata<QUICProtocol>? = harness.state?.clientHarness.getMetadata()
                    XCTAssertNotNil(clientMetadata)
                    if let clientMetadata {
                        let clientRemoteSize = clientMetadata.connectionMetadata?.remoteMaxDatagramFrameSize
                        XCTAssertNotNil(clientRemoteSize)
                        XCTAssertEqual(clientRemoteSize, 65535)
                    }
                    let serverMetadata: ProtocolMetadata<QUICProtocol>? = harness.state?.serverHarness.getMetadata()
                    XCTAssertNotNil(serverMetadata)
                    if let serverMetadata {
                        let serverRemoteSize = serverMetadata.connectionMetadata?.remoteMaxDatagramFrameSize
                        XCTAssertNotNil(serverRemoteSize)
                        XCTAssertEqual(serverRemoteSize, 65535)
                    }
                    expectation.fulfill()
                }
                let waitResult = XCTWaiter.wait(for: [expectation], timeout: 2.0)
                XCTAssertEqual(waitResult, .completed, "Remote datagram frame size fetch should complete")
            }
        )
    }

    // MARK: Unidirectional tests

    func testQUICHelloWorldUnidirectional() {
        QUICTestHarness().runQUICServerTestWithUnidirectionalStreams(
            streamCount: 4,
            dataBlock: Array("Hello World!".utf8),
            streamIDsToValidate: [2, 6, 10, 14]
        )
    }

    func testQUICHelloWorldUnidirectionalWithMaxStreamsUpdate() {
        // In this test the client should start with an initial max of 8 unidirectional streams.
        // We are telling the client to open 16 unidirectional streams so the server should
        // detect this and provide a MAX_STREAMS update to 16 and the client should be able to finish.
        QUICTestHarness().runQUICServerTestWithUnidirectionalStreams(
            streamCount: 16,
            dataBlock: Array("Hello World!".utf8),
            sendMaxStreamUpdate: true
        )
    }

    func testQUICHelloWorldUnidirectional50() {
        // Server advertises that the client can open 50 unidirectional streams
        let serverOptions = QUICProtocol.options()
        serverOptions.modifyConnectionOptions { $0.initialMaxStreamsUnidirectional = 50 }
        QUICTestHarness().runQUICServerTestWithUnidirectionalStreams(
            streamCount: 50,
            dataBlock: Array("Hello World!".utf8),
            serverOptions: serverOptions
        )
    }

    func testQUICUnidirectionalStreamHeldUntilTheApplicationClosesIt() {
        QUICTestHarness().runQUICUnidirectionalStreamHeldUntilTheApplicationClosesIt()
    }

    func testQUICHelloWorldUnidirectionalServerInitiated() {
        // Make sure that the server is able to initiate a outbound unidirectional stream to the client
        QUICTestHarness().runQUICServerInitiatedUnidirectionalStreams(
            streamCount: 2,
            dataBlock: Array("Hello World!".utf8),
            streamIDsToValidate: [3, 7]
        )
    }

    func testQUICHelloWorldUnidirectionalServerInitiated50() {
        // Make sure that the server is able to initiate 50 outbound unidirectional stream to the client
        // Server advertises that the client can open 50 unidirectional streams
        let clientOptions = QUICProtocol.options()
        // Set to 51 because the test starts creating streams at index 0 (not 1 like the other tests)
        clientOptions.modifyConnectionOptions { $0.initialMaxStreamsUnidirectional = 51 }
        QUICTestHarness().runQUICServerInitiatedUnidirectionalStreams(
            streamCount: 50,
            dataBlock: Array("Hello World!".utf8),
            clientOptions: clientOptions
        )
    }

    func testQUICClientUnidirectionalAndBidirectionalStreams() {
        // This test opens unidirectional and bidirectional streams on the same connection, similar to how HTTP3 would.
        QUICTestHarness().runQUICTestUnidirectionalAndBidirectionalStreams(
            streamCount: 4,
            dataBlock: Array("Hello World!".utf8)
        )
    }

    /// Aborting a stream sends RESET_STREAM and STOP_SENDING right away (RFC 9000 Sections 19.4
    /// and 19.5), not with whatever the connection sends next.
    func testQUICAbortingAStreamSendsResetStreamAndStopSendingRightAway() {
        QUICTestHarness().runQUICTestOnNewStream { harness, stream in
            let expectation = XCTestExpectation(description: "Abort the stream")
            harness.context.async {
                defer { expectation.fulfill() }
                guard let box = harness.state?.clientInstance.coreBox else {
                    return XCTFail("No client core")
                }
                XCTAssertTrue(stream.write(Array("Hello World!".utf8)))
                let resets = box.core.statistics[.txStreamResetFrames]
                stream.abortOutbound(error: .init(quicApplicationError: 7))
                XCTAssertEqual(box.core.statistics[.txStreamResetFrames], resets + 1, "RESET_STREAM sent")
                let stops = box.core.statistics[.txStreamStopSendingFrames]
                stream.abortInbound(error: .init(quicApplicationError: 7))
                XCTAssertEqual(box.core.statistics[.txStreamStopSendingFrames], stops + 1, "STOP_SENDING sent")
            }
            XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
        }
    }

    /// What the application writes between `.outboundDataBatchStart` and `.outboundDataBatchEnd`
    /// goes out when the batch ends.
    func testQUICOutboundDataBatchSendsWhenItEnds() {
        QUICTestHarness().runQUICTestOnNewStream { harness, stream in
            let expectation = XCTestExpectation(description: "Write a batch")
            harness.context.async {
                defer { expectation.fulfill() }
                guard let client = harness.state?.clientInstance, let box = client.coreBox else {
                    return XCTFail("No client core")
                }
                let sent = box.core.statistics[.txStreamBytes]
                client.fromExternal { eventContext in
                    _ = client.handleApplicationEvent(.outboundDataBatchStart, in: &eventContext)
                }
                XCTAssertTrue(stream.write(Array("Hello World!".utf8)))
                XCTAssertEqual(box.core.statistics[.txStreamBytes], sent, "held during the batch")
                client.fromExternal { eventContext in
                    _ = client.handleApplicationEvent(.outboundDataBatchEnd, in: &eventContext)
                }
                XCTAssertGreaterThan(box.core.statistics[.txStreamBytes], sent, "sent when the batch ends")
            }
            XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
        }
    }

    /// Writes and closing a stream within an outbound batch leave acting on the core to the batch
    /// end, which does it once.
    func testQUICOutboundDataBatchUpdatesTheCoreOnceAtItsEnd() {
        QUICTestHarness().runQUICTestOnNewStream { harness, stream in
            let expectation = XCTestExpectation(description: "Write a batch")
            harness.context.async {
                defer { expectation.fulfill() }
                guard let client = harness.state?.clientInstance, let box = client.coreBox else {
                    return XCTFail("No client core")
                }
                let sent = box.core.statistics[.txStreamBytes]
                client.fromExternal { eventContext in
                    _ = client.handleApplicationEvent(.outboundDataBatchStart, in: &eventContext)
                }
                let runs = client.coreAfterUpdateRuns
                for _ in 0..<10 {
                    XCTAssertTrue(stream.write(Array("Hello World!".utf8)))
                }
                XCTAssertEqual(client.coreAfterUpdateRuns, runs, "no update per write")
                stream.stop()
                XCTAssertEqual(client.coreAfterUpdateRuns, runs, "no update for the close")
                client.fromExternal { eventContext in
                    _ = client.handleApplicationEvent(.outboundDataBatchEnd, in: &eventContext)
                }
                XCTAssertEqual(client.coreAfterUpdateRuns, runs + 1, "one update for the batch")
                XCTAssertEqual(box.core.statistics[.txStreamBytes], sent + 120, "the whole batch went out")
            }
            XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
        }
    }

    /// Sending moves the loss detection deadline later; the armed timer stays, as firing early
    /// changes nothing.
    func testQUICTimerIsNotRearmedForLaterDeadlines() {
        QUICTestHarness().runQUICTestOnNewStream { harness, stream in
            let expectation = XCTestExpectation(description: "Write")
            harness.context.async {
                defer { expectation.fulfill() }
                guard let client = harness.state?.clientInstance, let box = client.coreBox else {
                    return XCTFail("No client core")
                }
                let rearms = client.coreTimerRearms
                for _ in 0..<20 {
                    XCTAssertTrue(stream.write(Array("Hello World!".utf8)))
                }
                XCTAssertLessThanOrEqual(client.coreTimerRearms, rearms + 1)
                guard let armed = box.armedDeadline, let deadline = box.core.nextDeadline else {
                    return XCTFail("No deadline")
                }
                XCTAssertLessThanOrEqual(armed, deadline, "armed no later than the core's deadline")
            }
            XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
        }
    }

    /// A datagram flow carries as much as the datagrams the path carries once PMTUD raised them.
    func testQUICDatagramFlowsGrowWithPMTUD() {
        let clientOptions = QUICProtocol.options()
        clientOptions.connectionOptions.pmtudIgnoreCost = true
        let serverOptions = QUICProtocol.options()
        serverOptions.connectionOptions.pmtudIgnoreCost = true

        QUICTestHarness().runQUICTest(
            datagram: true,
            dataBlock: Array("Hello World!".utf8),
            clientOptions: clientOptions,
            serverOptions: serverOptions,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Check the datagram size")
                harness.context.async {
                    defer { expectation.fulfill() }
                    guard let client = harness.state?.clientInstance, let box = client.coreBox else {
                        return XCTFail("No client core")
                    }
                    XCTAssertGreaterThan(box.core.maxDatagramSize, Constants.initialMSS)
                    var flows = 0
                    client.applyToAllSecondaryFlows { flow in
                        flows += 1
                        let flowIDSize = flow.flowID?.variableLengthSize ?? 0
                        let contextIDSize = flow.contextID?.variableLengthSize ?? 0
                        XCTAssertEqual(
                            flow.usableDatagramSize,
                            box.core.maxDatagramPayloadSize - flowIDSize - contextIDSize
                        )
                    }
                    XCTAssertGreaterThan(flows, 0, "no datagram flow")
                }
                XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
            }
        )
    }

    /// `Timer` runs an entry up to `Timer.timerThreshold` before its deadline. The core's timeout
    /// then counts as on time: what fell due goes out, and the timer is armed for the next
    /// deadline, rather than firing again for the same one.
    func testQUICCoreTimerFiredInsideTheLeewayCountsAsOnTime() {
        QUICTestHarness().runQUICTest(
            dataBlock: Array("Hello World!".utf8),
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Fire the core's timer early")
                harness.context.async {
                    defer { expectation.fulfill() }
                    guard let client = harness.state?.clientInstance, let box = client.coreBox else {
                        return XCTFail("No client core")
                    }
                    // A delayed ACK falls due before anything else. A timer armed for an earlier
                    // deadline would stay armed, so the timer is armed afresh for this one.
                    let deadline = client.now.advanced(by: .milliseconds(20))
                    client.fromExternal { eventContext in
                        box.core.acks[.applicationData].ackNeeded = false
                        box.core.acks[.applicationData].ackDeadline = deadline
                        box.armedDeadline = nil
                        client.coreAfterUpdate(in: &eventContext)
                    }
                    XCTAssertEqual(box.core.nextDeadline, deadline)
                    XCTAssertEqual(box.armedDeadline, deadline)

                    // One microsecond early, inside the leeway.
                    client.fromExternal { eventContext in
                        client.timer.timerFired(at: deadline.advanced(by: .microseconds(-1)), in: &eventContext)
                    }
                    XCTAssertNil(box.core.acks[.applicationData].ackDeadline, "the delayed ACK fell due")
                    XCTAssertFalse(box.core.acks[.applicationData].ackNeeded, "the ACK went out")
                    XCTAssertNotNil(box.armedDeadline, "the timer is armed for the next deadline")
                    XCTAssertEqual(box.armedDeadline, box.core.nextDeadline)
                }
                XCTAssertEqual(XCTWaiter.wait(for: [expectation], timeout: 2.0), .completed)
            }
        )
    }
}
#endif
#endif
#endif
