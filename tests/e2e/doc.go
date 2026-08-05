/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package e2e holds the network-namespace end-to-end tests (build tag: linux && e2e).
//
// These tests are Linux-only BY DESIGN. They use network namespaces + veth — which have
// no equivalent on Windows, macOS, or the BSDs — to run two real wireguard-go daemons in
// isolated network stacks and move real packets between them over UDP, WebSocket, and
// wstunnel. There is intentionally no netns-equivalent e2e for the other platforms: those
// targets are covered by the in-process integration tests (conn/*_test.go, all GOOS) plus
// the compile-only cross-build CI jobs. This is a stated design point, not a coverage gap.
package e2e
