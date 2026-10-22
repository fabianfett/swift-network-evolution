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

// The pure QUIC building blocks live in `QUICStateMachine`. Re-export them, including their SPI, so
// that `SwiftNetwork`'s API is unchanged for its clients.
@_spi(Essentials) @_spi(ProtocolProvider) @_exported import QUICStateMachine
