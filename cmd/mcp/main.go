package main

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func main() {
	apiURL := os.Getenv("MCTL_API_URL")
	if apiURL == "" {
		apiURL = "https://api.mctl.ai"
	}
	apiToken := os.Getenv("MCTL_API_TOKEN")

	// SetTenantOwnerChecker is deliberately not called here: the stdio binary
	// has one shared token and no per-caller identity, so the owner-only
	// erpact tools stay visible and the REST owner gate (requireErpactOwner)
	// is the enforcement. Production HTTP enforcement is the
	// SetTenantOwnerChecker call in internal/api/router.go.
	mctlSrv := mctlmcp.NewServer(apiURL, apiToken)
	supportCfg, err := mctlmcp.ParseSupportConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if supportCfg.BaseURL != "" {
		mctlSrv.SetSupportConfig(supportCfg)
	}
	mcpServer := mctlSrv.NewMCPServer()
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatal(err)
	}
}
