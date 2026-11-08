package rbac

import (
	"context"
	"path"
	"strings"

	"s3web/internal/model"
	"s3web/internal/store"
)

// Evaluator resolves in-app Access Grants for SSO Users, OIDC Groups, App-Managed Groups,
// GitHub Actions OIDC Workflows, and Service Accounts.
type Evaluator struct {
	store store.MetadataStore
}

// NewEvaluator creates a new in-app RBAC Evaluator.
func NewEvaluator(s store.MetadataStore) *Evaluator {
	return &Evaluator{store: s}
}

// Resolve evaluates all in-app Access Grants matching principal for targetKey (or "*" if targetKey == "").
// Default posture: authenticated SSO users receive Read-Only access unless granted Upload/Delete/Admin in-app.
func (e *Evaluator) Resolve(ctx context.Context, p *model.Principal, targetKey string) (model.EffectivePermissions, error) {
	grants, err := e.store.ListAccessGrants(ctx)
	if err != nil {
		return model.EffectivePermissions{}, err
	}

	targetKey = strings.TrimLeft(strings.TrimSpace(targetKey), "/")
	perm := model.EffectivePermissions{}

	// Baseline default: all authenticated human users (SSO or Local) and anonymous guests get Read-Only access by default
	if p.Type == model.PrincipalSSOUser || p.Type == model.PrincipalLocalUser || p.Type == model.PrincipalAnonymous {
		perm.CanRead = true
	}
	if p.IsLocalAdmin {
		perm.IsAdmin = true
		perm.CanRead = true
		perm.CanUpload = true
		perm.CanDelete = true
		perm.Grants = append(perm.Grants, "local-admin")
	}

	for _, g := range grants {
		if !subjectMatches(p, &g) {
			continue
		}
		if !prefixMatches(targetKey, g.Prefixes) {
			continue
		}
		if g.CanRead {
			perm.CanRead = true
		}
		if g.CanUpload {
			if len(g.AllowedExtensions) == 0 || targetKey == "" || strings.HasSuffix(targetKey, "/") || extensionMatches(targetKey, g.AllowedExtensions) {
				perm.CanUpload = true
			}
		}
		if g.CanDelete {
			perm.CanDelete = true
		}
		if g.IsAdmin {
			// Scoped grants cannot grant root administrative rights across the entire repository.
			// is_admin is only valid on global grants (empty prefixes or containing "*").
			if IsGlobalPrefixList(g.Prefixes) {
				perm.IsAdmin = true
				perm.CanRead = true
				perm.CanUpload = true
				perm.CanDelete = true
			}
		}
		perm.Grants = append(perm.Grants, g.ID)
	}

	return perm, nil
}

func subjectMatches(p *model.Principal, g *model.AccessGrant) bool {
	subID := strings.TrimSpace(g.SubjectID)
	isHumanUser := p.Type == model.PrincipalSSOUser || p.Type == model.PrincipalLocalUser
	switch g.SubjectType {
	case model.SubjectBuiltin:
		if strings.EqualFold(subID, "authenticated-users") && isHumanUser {
			return true
		}
		if strings.EqualFold(subID, "all-principals") || (p.Type == model.PrincipalAnonymous && strings.EqualFold(subID, "anonymous")) {
			return true
		}
	case model.SubjectSSOUser, model.SubjectLocalUser:
		if isHumanUser &&
			(strings.EqualFold(p.ID, subID) || strings.EqualFold(p.Username, subID) || strings.EqualFold(p.Email, subID)) {
			return true
		}
	case model.SubjectOIDCGroup:
		if isHumanUser {
			for _, grp := range p.OIDCGroups {
				if strings.EqualFold(strings.TrimSpace(grp), subID) {
					return true
				}
			}
		}
	case model.SubjectAppGroup:
		if isHumanUser {
			for _, grp := range p.AppGroups {
				if strings.EqualFold(strings.TrimSpace(grp), subID) {
					return true
				}
			}
		}
	case model.SubjectServiceAccount:
		if p.Type == model.PrincipalServiceAccount && strings.EqualFold(p.ID, subID) {
			return true
		}
	case model.SubjectGitHubWorkflow:
		if p.Type == model.PrincipalGitHubWorkflow {
			return matchGitHubWorkflowClaim(p, subID)
		}
	}
	return false
}

// matchGitHubWorkflowClaim matches GitHub OIDC subject/claim patterns such as:
// - "repo:my-org/iso-builder:ref:refs/heads/main"
// - "repo:my-org/iso-builder:ref:refs/tags/v*"
// - "repo:my-org/*:env:production"
// - "my-org/iso-builder"
func matchGitHubWorkflowClaim(p *model.Principal, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" {
		return true
	}
	repo := p.GitHubClaims["repository"]
	ref := p.GitHubClaims["ref"]
	env := p.GitHubClaims["environment"]
	sub := p.GitHubClaims["sub"]

	candidates := []string{
		sub,
		repo,
		"repo:" + repo + ":ref:" + ref,
		"repo:" + repo + ":env:" + env,
		"repo:" + repo + ":environment:" + env,
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if wildcardMatch(strings.ToLower(pattern), strings.ToLower(c)) {
			return true
		}
	}
	return false
}

func prefixMatches(targetKey string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	// If checking global UI permissions (targetKey == ""), match if any prefix is configured
	if targetKey == "" {
		return true
	}
	for _, rawPattern := range patterns {
		pat := strings.TrimLeft(strings.TrimSpace(rawPattern), "/")
		if pat == "" || pat == "*" || pat == "**" {
			return true
		}
		if strings.HasSuffix(pat, "/*") {
			base := strings.TrimSuffix(pat, "*")
			if strings.HasPrefix(targetKey, base) || strings.TrimSuffix(base, "/") == targetKey {
				return true
			}
		}
		if wildcardMatch(strings.ToLower(pat), strings.ToLower(targetKey)) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	// Support prefix glob with '*' even across slashes
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	if !strings.HasSuffix(name, parts[len(parts)-1]) {
		return false
	}
	idx := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		sub := parts[i]
		pos := strings.Index(name[idx:], sub)
		if pos == -1 {
			return false
		}
		idx += pos + len(sub)
	}
	if matched, err := path.Match(pattern, name); err == nil && matched {
		return true
	}
	return idx <= len(name)-len(parts[len(parts)-1])
}

// IsGlobalPrefixList returns true if prefixes is empty or includes a global wildcard pattern ("*", "**").
func IsGlobalPrefixList(prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" || trimmed == "*" || trimmed == "**" {
			return true
		}
	}
	return false
}

func extensionMatches(key string, exts []string) bool {
	if len(exts) == 0 {
		return true
	}
	cleanKey := strings.TrimRight(strings.TrimSpace(key), "/")
	lower := strings.ToLower(cleanKey)
	for _, raw := range exts {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		if e == "*" || e == "all" || e == ".*" {
			return true
		}
		e = strings.TrimPrefix(e, "*")
		e = strings.TrimRight(e, ".")
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

