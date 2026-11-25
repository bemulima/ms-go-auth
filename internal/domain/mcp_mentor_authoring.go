package domain

const (
	MCPMentorAuthoringPurpose   = "MCP_MENTOR_AUTHORING_V1"
	MCPMentorCourseDraftScope   = "mentor:courses:write"
	MCPMentorTaskDraftScope     = "mentor:tasks:write"
	MCPMentorCoursePublishScope = "mentor:courses:publish"
	MCPMentorTaskPublishScope   = "mentor:tasks:publish"
)

func MCPMentorAuthoringScopes() []string {
	return []string{MCPMentorCourseDraftScope, MCPMentorTaskDraftScope, MCPMentorCoursePublishScope, MCPMentorTaskPublishScope}
}

func IsMCPMentorAuthoringScope(scope string) bool {
	switch scope {
	case MCPMentorCourseDraftScope, MCPMentorTaskDraftScope, MCPMentorCoursePublishScope, MCPMentorTaskPublishScope:
		return true
	}
	return false
}
