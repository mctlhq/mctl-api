package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/server"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func main() {
	// MCP servers log to stderr so stdout stays clean for the MCP protocol.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	apiURL := envOr("MCTL_API_URL", "https://api.mctl.ai")
	apiToken := resolveToken()

	if apiToken == "" {
		slog.Warn("no API token found — running in unauthenticated mode (read-only ops only)")
	} else {
		slog.Info("authenticated", "tokenSource", tokenSource())
	}

	slog.Info("mctl-mcp starting", "apiURL", apiURL)

	s := mctlmcp.NewServer(apiURL, apiToken)
	mcpServer := s.NewMCPServer()

	if err := server.ServeStdio(mcpServer); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

// resolveToken returns the API token from the environment or from gh CLI.
// Priority: MCTL_API_TOKEN > gh auth token
func resolveToken() string {
	if t := os.Getenv("MCTL_API_TOKEN"); t != "" {
		return t
	}
	// Try gh CLI (same auth the mctl CLI uses).
	out, err := exec.Command("gh", "auth", "token").Output()
	if err == nil {
		t := strings.TrimSpace(string(out))
		if t != "" {
			return t
		}
	}
	return ""
}

func tokenSource() string {
	if os.Getenv("MCTL_API_TOKEN") != "" {
		return "MCTL_API_TOKEN env"
	}
	return "gh auth token"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
