// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import (
	"context"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// registerPrompts registers MCP Prompts on the server.
func (s *Server) registerPrompts() {
	// 1. onboard_service prompt
	onboardPrompt := mcplib.NewPrompt("onboard_service",
		mcplib.WithPromptDescription("Guided workflow for onboarding a microservice to the mctl platform"),
		mcplib.WithArgument("team_name", mcplib.ArgumentDescription("Tenant or team name"), mcplib.RequiredArgument()),
		mcplib.WithArgument("component_name", mcplib.ArgumentDescription("Microservice component name"), mcplib.RequiredArgument()),
	)

	s.mcpServer.AddPrompt(onboardPrompt, func(ctx context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
		args := req.Params.Arguments
		team := args["team_name"]
		comp := args["component_name"]

		text := fmt.Sprintf(
			"Please guide me through onboarding the service '%s' for team '%s'.\n"+
				"Check list of steps:\n"+
				"1. Verify team '%s' exists using mctl_get_tenant.\n"+
				"2. Confirm GitHub repository access with mctl_list_repos.\n"+
				"3. Trigger service onboarding using mctl_deploy_service with action='onboard'.\n"+
				"4. Verify deployment status using mctl_get_service_status.",
			comp, team, team,
		)

		return mcplib.NewGetPromptResult(
			"Service Onboarding Workflow",
			[]mcplib.PromptMessage{
				mcplib.NewPromptMessage(mcplib.RoleUser, mcplib.NewTextContent(text)),
			},
		), nil
	})

	// 2. troubleshoot_incident prompt
	troubleshootPrompt := mcplib.NewPrompt("troubleshoot_incident",
		mcplib.WithPromptDescription("Interactive incident triage and root cause analysis prompt"),
		mcplib.WithArgument("incident_id", mcplib.ArgumentDescription("Incident ID to investigate"), mcplib.RequiredArgument()),
	)

	s.mcpServer.AddPrompt(troubleshootPrompt, func(ctx context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
		args := req.Params.Arguments
		incidentID := args["incident_id"]

		text := fmt.Sprintf(
			"Help me triage incident '%s'.\n"+
				"Follow this diagnostic runbook:\n"+
				"1. Fetch incident details with mctl_get_incident.\n"+
				"2. Retrieve recent workflow and service logs with mctl_get_service_logs.\n"+
				"3. Check resource usage metrics with mctl_get_resource_usage.\n"+
				"4. Summarize root cause and acknowledge the incident with mctl_acknowledge_incident.",
			incidentID,
		)

		return mcplib.NewGetPromptResult(
			"Incident Triage Runbook",
			[]mcplib.PromptMessage{
				mcplib.NewPromptMessage(mcplib.RoleUser, mcplib.NewTextContent(text)),
			},
		), nil
	})

	// 3. deploy_service prompt
	deployPrompt := mcplib.NewPrompt("deploy_service",
		mcplib.WithPromptDescription("Guided deployment and verification prompt for platform services"),
		mcplib.WithArgument("team_name", mcplib.ArgumentDescription("Tenant or team name"), mcplib.RequiredArgument()),
		mcplib.WithArgument("component_name", mcplib.ArgumentDescription("Service name"), mcplib.RequiredArgument()),
		mcplib.WithArgument("git_tag", mcplib.ArgumentDescription("Git tag or image tag to deploy"), mcplib.RequiredArgument()),
	)

	s.mcpServer.AddPrompt(deployPrompt, func(ctx context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
		args := req.Params.Arguments
		team := args["team_name"]
		comp := args["component_name"]
		tag := args["git_tag"]

		text := fmt.Sprintf(
			"Execute production deployment for '%s/%s' with tag '%s'.\n"+
				"Verification steps:\n"+
				"1. Trigger deployment using mctl_deploy_service (action='deploy', team_name='%s', component_name='%s', git_tag='%s').\n"+
				"2. Monitor workflow status using mctl_get_workflow_status.\n"+
				"3. Confirm service health using mctl_get_service_status.",
			team, comp, tag, team, comp, tag,
		)

		return mcplib.NewGetPromptResult(
			"Service Deployment Guide",
			[]mcplib.PromptMessage{
				mcplib.NewPromptMessage(mcplib.RoleUser, mcplib.NewTextContent(text)),
			},
		), nil
	})
}
