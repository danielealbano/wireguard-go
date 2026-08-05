/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package metrics

import "encoding/base64"

// Version is set by the daemon (main) to the build version before registration.
var Version = "dev"

func peerLabel(pk [32]byte) string { return base64.StdEncoding.EncodeToString(pk[:]) }
