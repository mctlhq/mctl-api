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

	mcpServer := mctlmcp.NewServer(apiURL, apiToken).NewMCPServer()
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatal(err)
	}
}
