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

// Note: It is CaseIterable only so that tests can ensure it checks all states
enum QUICPathState: CustomStringConvertible, CaseIterable {
    case invalid  // initial state. RX/TX NOT allowed
    case routeAvailable  // path manager has indicated this is a potential path. RX/TX NOT allowed
    case routeEstablished  // hardware backing the path is ready to send and receive. RX/TX NOT allowed
    case cidAssigned  // path is ready for QUIC transactions. RX/TX allowed
    case probing  // path is being validated. RX/TX allowed
    case validated  // path validation is complete. RX/TX allowed
    case unreachable  // path connectivity is lost. RX/TX NOT allowed
    case closing  // path is going away. RX/TX NOT allowed
    case routeUnavailable  // path has gone away. RX/TX NOT allowed

    var description: String {
        switch self {
        case .invalid: return "invalid"
        case .routeAvailable: return "routeAvailable"
        case .routeEstablished: return "routeEstablished"
        case .cidAssigned: return "cidAssigned"
        case .probing: return "probing"
        case .validated: return "validated"
        case .unreachable: return "unreachable"
        case .closing: return "closing"
        case .routeUnavailable: return "routeUnavailable"
        }
    }

    init(state: QUICPathState = .invalid) {
        self = state
    }

    func isValidStateChange(to newState: QUICPathState) -> Bool {
        switch (self, newState) {
        case (.invalid, .routeAvailable),
            (.invalid, .routeEstablished),
            (.routeAvailable, .routeEstablished),
            (.routeAvailable, .routeUnavailable),
            (.routeEstablished, .cidAssigned),
            (.routeEstablished, .routeUnavailable),
            (.cidAssigned, .probing),
            (.cidAssigned, .routeUnavailable),
            (.probing, .validated),
            (.probing, .unreachable),
            (.probing, .routeUnavailable),
            (.validated, .unreachable),
            (.validated, .probing),
            (.validated, .closing),
            (.validated, .routeEstablished),
            (.validated, .routeUnavailable),
            (.unreachable, .closing),
            (.unreachable, .routeUnavailable),
            (.closing, .routeUnavailable):
            return true
        default:
            return false
        }
    }

    var isOpenForSending: Bool {
        self == .cidAssigned || self == .probing || self == .validated
    }

    var isInvalid: Bool {
        self == .invalid
    }

    var isValidated: Bool {
        self == .validated
    }

    var isRouteEstablished: Bool {
        // All states other than available / unavailable have an established route
        self != .invalid && self != .routeAvailable && self != .routeUnavailable
    }

    var isProbing: Bool {
        self == .probing
    }

    var isUnusable: Bool {
        self == .routeUnavailable || self == .unreachable
    }
}

@_spi(ProtocolProvider)
@available(Network 0.1.0, *)
public final class QUICPath: MultiplexingDatagramPath<
    QUICConnection,
    BaseOutboundDatagramLinkage
>, Equatable, PrefixedLoggable
{
    /// The path's protocol state; the class adds the framework path around it.
    var protocolState: QUICPathProtocolState

    typealias Flags = QUICPathProtocolState.Flags

    private(set) var state: QUICPathState {
        get { protocolState.state }
        set { protocolState.state = newValue }
    }
    var priority: Int {  // Relative priority to other paths, used to gate migration decisions
        get { protocolState.priority }
        set { protocolState.priority = newValue }
    }
    var interface: Interface?
    var localEndpoint: Endpoint?
    var remoteEndpoint: Endpoint?

    private(set) var dcid: QUICConnectionID? {  // The DCID we assigned before probing
        get { protocolState.dcid }
        set { protocolState.dcid = newValue }
    }
    private(set) var scid: QUICConnectionID? {  // Contains the SCID we expect to see once we migrate.
        get { protocolState.scid }
        set { protocolState.scid = newValue }
    }

    var pathStatistics: Statistics {
        _read { yield protocolState.pathStatistics }
        _modify { yield &protocolState.pathStatistics }
    }

    var initialMSS: Int {
        get { protocolState.initialMSS }
        set { protocolState.initialMSS = newValue }
    }
    var mss: Int {
        get { protocolState.mss }
        set { protocolState.mss = newValue }
    }
    var maximumMSS: Int {
        get { protocolState.maximumMSS }
        set { protocolState.maximumMSS = newValue }
    }
    var minimumMSS: Int {
        get { protocolState.minimumMSS }
        set { protocolState.minimumMSS = newValue }
    }

    private var flags: Flags {
        get { protocolState.flags }
        set { protocolState.flags = newValue }
    }

    var isInitialPath: Bool {
        get { flags.contains(.isInitialPath) }
        set { if newValue { flags.insert(.isInitialPath) } else { flags.remove(.isInitialPath) } }
    }
    var isPrimaryPath: Bool {
        get { flags.contains(.isPrimaryPath) }
        set { if newValue { flags.insert(.isPrimaryPath) } else { flags.remove(.isPrimaryPath) } }
    }
    var spinValue: Bool {
        get { flags.contains(.spinValue) }
        set { if newValue { flags.insert(.spinValue) } else { flags.remove(.spinValue) } }
    }
    var isPreferredAddress: Bool {
        get { flags.contains(.isPreferredAddress) }
        set { if newValue { flags.insert(.isPreferredAddress) } else { flags.remove(.isPreferredAddress) } }
    }

    var hasPreAssignedCIDs: Bool {
        get { flags.contains(.hasPreAssignedCIDs) }
        set { if newValue { flags.insert(.hasPreAssignedCIDs) } else { flags.remove(.hasPreAssignedCIDs) } }
    }
    var reportedIdleEvent: Bool {
        get { flags.contains(.reportedIdleEvent) }
        set { if newValue { flags.insert(.reportedIdleEvent) } else { flags.remove(.reportedIdleEvent) } }
    }

    package var log: LogPrefixer {
        parentProtocol.logPrefixer
    }

    override public func asUpperLinkage() -> LowerProtocol.PairedUpperLinkage {
        BaseInboundDatagramLinkage(quicPath: self)
    }

    public static func == (lhs: QUICPath, rhs: QUICPath) -> Bool {
        lhs.pathIdentifier == rhs.pathIdentifier
    }

    var isOpenForSending: Bool { state.isOpenForSending }

    var isValidated: Bool { state.isValidated }

    var isProbing: Bool { state.isProbing }

    var isRouteEstablished: Bool { state.isRouteEstablished }

    func changeState(to newState: QUICPathState) {
        guard state.isValidStateChange(to: newState) else {
            log.fault("Invalid path transition: \(state) -> \(newState)")
            return
        }
        log.debug("Path state change: \(state) -> \(newState)")
        state = newState
    }

    func set(
        interface: Interface?,
        priority: Int,
        isInitial: Bool,
    ) {
        self.isInitialPath = isInitial
        self.priority = priority
        self.interface = interface

        if isInitial {
            // initial paths start with fully established routes
            self.state = .routeEstablished
        }
        self.setup()

        log.debug(
            "Set up new path \(pathIdentifier) (\(priority)), \(interface?.description ?? "<none>")"
        )
    }

    // These take the generic `fromExternal` entry point, which embedded Swift cannot specialize,
    // and nothing but the tests calls them.
    #if !NETWORK_EMBEDDED
    /// Creates a path from outside the protocol stack, for tests only.
    ///
    /// Path creation registers an event state, which needs the event context. Code already
    /// running inside the stack should use `init(parent:in:)` and thread its own state in;
    /// this convenience is for external entry points such as tests.
    ///
    /// A path built this way isn't in the parent's `multiplexingPaths`, so nothing tears it down.
    /// Pair it with `destroyFromExternalTest()` before letting it go.
    static func makeFromExternalTest(parent: QUICConnection) -> Self {
        parent.fromExternal { eventContext in
            Self(parent: parent, in: &eventContext)
        }
    }

    /// Destroys a path built with `makeFromExternalTest(parent:)`, for tests only.
    ///
    /// This is an external entry point; code inside the stack calls `destroy(in:)` with the
    /// state it already holds.
    func destroyFromExternalTest() {
        fromExternal { eventContext in
            var selfVar = self
            selfVar.destroy(in: &eventContext)
        }
    }
    #endif

    required init(parent: QUICConnection, in eventContext: inout NetworkContext.EventContext) {
        self.protocolState = QUICPathProtocolState()
        super.init(parent: parent, in: &eventContext)
    }

    private func setup() {
        self.initialMSS = parentProtocol.initialMSS
        self.maximumMSS =
            CorePMTUD.maximumMTU - (IPProtocol.ipv6HeaderLength + UDPProtocol.headerLength)
        self.minimumMSS =
            CorePMTUD.minimumMTU - (IPProtocol.ipv6HeaderLength + UDPProtocol.headerLength)

        self.mss = parentProtocol.initialMSS
        if !self.isInitialPath, let interface {
            // Search for other paths that share the same interface that have calculated another MSS
            var foundMSS = false
            parentProtocol.applyToAllPaths { otherPath in
                if !foundMSS, interface == otherPath.interface, otherPath.mss > 0 {
                    self.mss = otherPath.mss
                    log.debug(
                        "MSS \(otherPath.mss) copied from path \(otherPath.pathIdentifier.description), since they share the same interface \(interface)"
                    )
                    foundMSS = true
                }
            }
        }

        self.spinValue = parentProtocol.initialSpinValue
    }

    func setSCID(_ scid: QUICConnectionID) {
        self.scid = scid
        log.datapath(
            "Assigning SCID \(scid.description) to path ID \(self.pathIdentifier)"
        )
    }

    func assignDCID(_ dcid: QUICConnectionID, in eventContext: inout NetworkContext.EventContext) {
        self.dcid = dcid
        if case .routeEstablished = state {
            changeState(to: .cidAssigned)
            if let localEndpoint, let remoteEndpoint,
                case .address(let localAddress) = localEndpoint.type,
                case .address(let remoteAddress) = remoteEndpoint.type
            {
                // If the cid is now assigned we can send and receive on the path
                let pathInfo = QUICPathInfo(
                    isValidated: self.isValidated,
                    remote: remoteAddress,
                    local: localAddress
                )
                parentProtocol.deliverNetworkProtocolEvent(
                    flow: .allFlows,
                    event: .init(quicEvent: .pathCIDAssigned(pathInfo)),
                    in: &eventContext
                )
            }
        }
        log.datapath(
            "Assigning DCID \(dcid.description) to path ID \(self.pathIdentifier)"
        )
    }

}

#endif
