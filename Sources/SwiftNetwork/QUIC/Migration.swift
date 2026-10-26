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

@available(Network 0.1.0, *)
extension QUICConnection {
    public func handlePathChanged(
        path pathID: MultiplexingPathIdentifier,
        event: MultiplexingPathEvent,
        isPrimary: Bool,
        in eventContext: inout NetworkContext.EventContext
    ) {
        // The core doesn't migrate when the peer disabled active migration (RFC 9000 Section
        // 18.2, `QUICConnectionCore.probePath`).
        log.debug("Path \(pathID.description) changed to \(event), primary: \(isPrimary)")

        guard let path = path(for: pathID) else {
            log.error("Path \(pathID.description) not found, ignoring")
            return
        }
        switch event {
        case .available:
            if !path.isRouteEstablished {
                path.set(interface: nil, priority: 0, isInitial: false)
                path.changeState(to: .routeAvailable)
                if self.state == .connected {
                    log.debug("Bringing up path \(pathID.description)")
                    invokeEstablish(path: pathID, in: &eventContext)
                }
            }
            break
        case .established:
            if !path.isRouteEstablished {
                path.changeState(to: .routeEstablished)
            }
            // The core validates a path once a packet arrives on it.
            break
        case .unavailable:
            self.coreForgetPath(path)
            path.changeState(to: .routeUnavailable)
            break
        }

        if isServer {
            allPathIdentifiers { id in
                guard var path = multiplexingPaths[id], path.state == .routeUnavailable, path !== currentPath else {
                    return
                }
                self.coreForgetPath(path)
                path.destroy(in: &eventContext)
                multiplexingPaths.removeValue(forKey: id)
            }
        }

        log.debug("Existing paths:")
        applyToAllPaths { path in
            log.debug(
                "Path \(path.pathIdentifier) \(path.state) over \(path.interface?.description ?? "nil")"
            )
        }
        // Notify the stack about a path change event
        if case .available(let local, let remote, _, _) = event,
            let local, let remote,
            case .address(let localAddress) = local.type,
            case .address(let remoteAddress) = remote.type
        {
            path.localEndpoint = local
            path.remoteEndpoint = remote
            let pathInfo = QUICPathInfo(
                isValidated: path.isValidated,
                remote: remoteAddress,
                local: localAddress
            )
            deliverNetworkProtocolEvent(
                flow: .allFlows,
                event: .init(quicEvent: .pathChanged(pathInfo)),
                in: &eventContext
            )
        }

        // This is a new primary path. Migrate to it if we are the client.
        if !isServer, path != currentPath, isPrimary, path.isRouteEstablished {
            self.coreMigrate(to: path, in: &eventContext)
        }
    }
}
#endif
