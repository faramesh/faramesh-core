package sandbox

import (
	"fmt"
	"strconv"
)

// ProxyEnvVars returns HTTP/HTTPS/SOCKS5 proxy environment variables
// pointing at Faramesh's local governance proxy. This is the universal
// network interception mechanism — works on Linux, macOS, and Windows
// for any agent that respects standard proxy environment variables.
func ProxyEnvVars(proxyPort int) []string {
	addr := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	return []string{
		"HTTP_PROXY=" + addr,
		"HTTPS_PROXY=" + addr,
		"http_proxy=" + addr,
		"https_proxy=" + addr,
		"ALL_PROXY=socks5://127.0.0.1:" + strconv.Itoa(proxyPort),
		"NO_PROXY=localhost,127.0.0.1,::1",
	}
}
