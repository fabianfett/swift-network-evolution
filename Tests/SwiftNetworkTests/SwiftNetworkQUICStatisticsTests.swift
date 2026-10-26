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

import XCTest

#if !targetEnvironment(simulator) && (os(iOS) || os(macOS) || os(Linux) || os(Android))

#if canImport(SwiftNetwork)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import SwiftNetwork
#elseif canImport(Network)
@_spi(Essentials) @_spi(ProtocolProvider) @testable import Network
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

#if IMPORT_SWIFTTLS
#if canImport(SwiftTLS)

@available(Network 0.1.0, *)
final class SwiftNetworkQUICStatisticsTests: NetTestCase {
    func testQUICStatisticsForOneStream() throws {
        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait to validate stats")
                harness.context.async {
                    defer { expectation.fulfill() }

                    let clientConnectionStats = harness.state?.clientInstance.stats.connectionStatistics
                    XCTAssertNotNil(clientConnectionStats)
                    guard let clientConnectionStats else {
                        return
                    }
                    let totalSentBytes = 10240 * 4
                    XCTAssertTrue(clientConnectionStats[.rxBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.rxPackets]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txPackets]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txStreamBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.rxStreamBytes]! > 0)
                    XCTAssertEqual(clientConnectionStats[.txStreamBytes]!, totalSentBytes)
                    XCTAssertEqual(clientConnectionStats[.rxStreamBytes]!, totalSentBytes)
                    XCTAssertEqual(clientConnectionStats[.outboundBidirectionalStreams], 1)
                }
                self.wait(for: [expectation], timeout: 5.0)
            }
        )
    }

    func testQUICStatisticsForMultipleStreams() throws {
        QUICTestHarness().runQUICTest(
            streamCount: 6,
            blockSize: 10240,
            blockCount: 4,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait to validate stats")
                harness.context.async {
                    defer { expectation.fulfill() }

                    let clientConnectionStats = harness.state?.clientInstance.stats.connectionStatistics
                    XCTAssertNotNil(clientConnectionStats)
                    guard let clientConnectionStats else {
                        return
                    }
                    XCTAssertTrue(clientConnectionStats[.rxBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.rxPackets]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txPackets]! > 0)
                    XCTAssertEqual(clientConnectionStats[.outboundBidirectionalStreams], 6)
                    XCTAssertEqual(clientConnectionStats[.txInitialCryptoFrames], 1)
                    XCTAssertEqual(clientConnectionStats[.rxInitialCryptoFrames], 1)
                    XCTAssertEqual(clientConnectionStats[.txHandshakeCryptoFrames], 1)
                    XCTAssertEqual(clientConnectionStats[.rxHandshakeCryptoFrames], 1)
                    XCTAssertEqual(clientConnectionStats[.connectionAttempts], 1)
                    XCTAssertTrue(clientConnectionStats[.rxStreamFrames]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txStreamFrames]! > 0)
                    XCTAssertTrue(clientConnectionStats[.txStreamBytes]! > 0)
                    XCTAssertTrue(clientConnectionStats[.rxStreamBytes]! > 0)
                }
                self.wait(for: [expectation], timeout: 5.0)
            }
        )
    }

    /// The RTT and congestion state of the snapshot are the core's, measured over a link that
    /// delays what the client sends by about 10 ms (the timer runs entries a little early).
    func testQUICDataTransferSnapshotHasTheCoresRTTAndCongestionState() throws {
        QUICTestHarness().runQUICTest(
            blockSize: 10240,
            blockCount: 4,
            clientLinkDelay: .milliseconds(10),
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait to validate the snapshot")
                harness.context.async {
                    defer { expectation.fulfill() }
                    let instances = [harness.state?.clientInstance, harness.state?.serverInstance]
                    for (instance, side) in zip(instances, ["client", "server"]) {
                        guard let instance, let box = instance.coreBox else {
                            XCTFail("No \(side) core")
                            continue
                        }
                        var snapshot = DataTransferSnapshot()
                        instance.updateDataTransferSnapshot(flow: .allFlows, &snapshot)
                        XCTAssertEqual(snapshot.transportSmoothedRTT, box.core.smoothedRTT, side)
                        XCTAssertEqual(snapshot.transportMinimumRTT, box.core.minRTT, side)
                        XCTAssertEqual(snapshot.transportCurrentRTT, box.core.latestRTT, side)
                        XCTAssertEqual(snapshot.transportRTTVariance, box.core.rttVariance, side)
                        // Measured, not the initial RTT of 333 ms (RFC 9002 Section 6.2.2).
                        XCTAssertGreaterThanOrEqual(snapshot.transportMinimumRTT, .milliseconds(5), side)
                        XCTAssertLessThan(snapshot.transportSmoothedRTT, .milliseconds(300), side)
                        XCTAssertGreaterThanOrEqual(snapshot.transportCurrentRTT, .milliseconds(5), side)
                        XCTAssertEqual(snapshot.transportCongestionWindow, UInt64(box.core.congestionWindow), side)
                        XCTAssertGreaterThan(snapshot.transportCongestionWindow, 0, side)
                        // Nothing was lost: slow start never ended.
                        XCTAssertEqual(snapshot.transportSlowStartThreshold, .max, side)
                    }
                }
                self.wait(for: [expectation], timeout: 5.0)
            }
        )
    }

    /// The handshake RTT and L4S of the establishment report are the core's.
    func testQUICEstablishmentReportHasTheCoresHandshakeRTT() throws {
        QUICTestHarness().runQUICTest(
            dataBlock: Array("Hello World!".utf8),
            clientLinkDelay: .milliseconds(10),
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait to validate the report")
                harness.context.async {
                    defer { expectation.fulfill() }
                    let instances = [harness.state?.clientInstance, harness.state?.serverInstance]
                    for (instance, side) in zip(instances, ["client", "server"]) {
                        guard let instance, let box = instance.coreBox else {
                            XCTFail("No \(side) core")
                            continue
                        }
                        let report = try? XCTUnwrap(instance.protocolEstablishmentReport, side)
                        let handshakeRTT = try? XCTUnwrap(box.core.handshakeRTT, side)
                        XCTAssertEqual(report?.handshakeRTT, handshakeRTT, side)
                        XCTAssertGreaterThanOrEqual(report?.handshakeRTT ?? .zero, .milliseconds(5), side)
                        XCTAssertLessThan(report?.handshakeRTT ?? .zero, .milliseconds(300), side)
                        XCTAssertEqual(report?.l4sEnabled, false, side)
                    }
                }
                self.wait(for: [expectation], timeout: 5.0)
            }
        )
    }

    func testQUICEstablishmentReportHasL4SFromTheCore() throws {
        let clientOptions = QUICProtocol.options()
        clientOptions.connectionOptions.enableL4S = true
        let serverOptions = QUICProtocol.options()
        serverOptions.connectionOptions.enableL4S = true
        QUICTestHarness().runQUICTest(
            dataBlock: Array("Hello World!".utf8),
            clientOptions: clientOptions,
            serverOptions: serverOptions,
            afterData: { harness in
                let expectation = XCTestExpectation(description: "Wait to validate the report")
                harness.context.async {
                    defer { expectation.fulfill() }
                    let instances = [harness.state?.clientInstance, harness.state?.serverInstance]
                    for (instance, side) in zip(instances, ["client", "server"]) {
                        XCTAssertEqual(instance?.coreBox?.core.l4sEnabled, true, side)
                        XCTAssertEqual(instance?.protocolEstablishmentReport?.l4sEnabled, true, side)
                    }
                }
                self.wait(for: [expectation], timeout: 5.0)
            }
        )
    }
}

#endif
#endif
#endif
