/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// wstunnelDefaultPathPrefix is wstunnel's default client upgrade path prefix
// (wstunnel src/config.rs: DEFAULT_CLIENT_UPGRADE_PATH_PREFIX = "v1"), used when
// the endpoint URL carries no path so the request targets /v1/events like the
// stock wstunnel client. A custom server prefix is given via the endpoint URL path.
const wstunnelDefaultPathPrefix = "v1"

// wsUpgradeRequest builds the dial URL, HTTP header, and subprotocols for an
// endpoint's dialect. Standard: verbatim URL, optional Authorization: Bearer.
// Wstunnel: /<prefix>/events path + Sec-WebSocket-Protocol: v1, authorization.bearer.<jwt>.
func wsUpgradeRequest(e *WSEndpoint) (dialURL string, header http.Header, subprotocols []string, err error) {
	header = http.Header{}
	switch e.dialect {
	case wsDialectStandard:
		if e.bearer != "" {
			header.Set("Authorization", "Bearer "+e.bearer)
		}
		return e.url, header, nil, nil
	case wsDialectWstunnel:
		u, perr := url.Parse(e.url)
		if perr != nil {
			return "", nil, nil, fmt.Errorf("wstunnel endpoint %q: %w", e.url, perr)
		}
		prefix := strings.Trim(u.Path, "/")
		if prefix == "" {
			prefix = wstunnelDefaultPathPrefix // no path given => wstunnel's default /v1/events
		}
		u.Path = "/" + prefix + "/events"
		token, jerr := wstunnelJWT(e.target, wsRandomSecret())
		if jerr != nil {
			return "", nil, nil, jerr
		}
		subprotocols = []string{"v1", "authorization.bearer." + token}
		if e.bearer != "" { // optional basic-auth: e.bearer is base64(user:pass)
			header.Set("Authorization", "Basic "+e.bearer)
		}
		return u.String(), header, subprotocols, nil
	default:
		return "", nil, nil, fmt.Errorf("unknown ws dialect %d", e.dialect)
	}
}
