// Package conformance probes an OAuth authorization server (or an MCP
// resource server, by walking the agent discovery loop) and reports how
// ready it is for MCP agent auth, as a capability matrix over two profiles:
// MCP Core (the MUSTs) and MCP Agent-Auth Extended (RFC 8693, DPoP).
package conformance
