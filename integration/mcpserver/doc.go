// Package main is a config-driven, aoa-guarded MCP server used as a live
// aoa-conform target. It serves an official go-sdk MCP server (two tools)
// behind aoa Bearer/DPoP middleware, delegating to a configurable OAuth
// provider (Keycloak shipped; Hydra/Okta config-ready).
package main
