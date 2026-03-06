package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/server"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	apiURL := envOr("MCTL_API_URL", "http://localhost:8080")
	apiToken := os.Getenv("MCTL_API_TOKEN")

	slog.Info("mctl-mcp starting", "apiURL", apiURL)

	s := mctlmcp.NewServer(apiURL, apiToken)
	mcpServer := s.NewMCPServer()

	// Run as stdio transport (for Claude Desktop / Cursor).
	if err := server.ServeStdio(mcpServer); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
