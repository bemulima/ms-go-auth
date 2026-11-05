package domain

const (
	KnowledgeGraphReviewPermission              = "knowledge_graph.review"
	ReviewerPermissionDecisionIssuer            = "ms-go-rbac"
	ReviewerPermissionDecisionAudience          = "ms-go-auth-knowledge-review-permission-decision"
	ReviewerPermissionDecisionType              = "knowledge_graph_permission_decision"
	ReviewerPermissionDecisionPurpose           = "RBAC_AUTH_KNOWLEDGE_GRAPH_REVIEW_DECISION_V1"
	ReviewerPermissionDecisionTTLSeconds        = 15
	ReviewerPermissionDecisionMaxAgeSeconds     = 30
	ReviewerPermissionDecisionFutureSkewSeconds = 5
)
