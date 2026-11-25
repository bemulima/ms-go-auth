package domain

const MCPMentorManagementPurpose = "MCP_MENTOR_MANAGEMENT_V1"

func MCPMentorManagementScopes() []string {
	return []string{"mentor:profile:write", "mentor:offers:write", "mentor:students:write", "mentor:cohorts:write", "mentor:schedule:write", "mentor:offers:publish", "mentor:schedule:cancel", "mentor:cohorts:respond", "mentor:students:feedback"}
}

func IsMCPMentorManagementScope(scope string) bool {
	switch scope {
	case "mentor:profile:write", "mentor:offers:write", "mentor:students:write", "mentor:cohorts:write", "mentor:schedule:write", "mentor:offers:publish", "mentor:schedule:cancel", "mentor:cohorts:respond", "mentor:students:feedback":
		return true
	}
	return false
}
