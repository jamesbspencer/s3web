package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"s3web/internal/model"
)

var (
	ErrNotFound = errors.New("item not found")
)

// MetadataStore abstracts the DynamoDB Single-Table persistence layer for object metadata,
// directory indexes, per-item access logs, in-app access grants, app groups, and service accounts.
type MetadataStore interface {
	// Object Metadata & Directory Listing
	PutObjectMeta(ctx context.Context, meta *model.ObjectMeta) error
	GetObjectMeta(ctx context.Context, key string) (*model.ObjectMeta, error)
	DeleteObjectMeta(ctx context.Context, key string) error
	ListDirectory(ctx context.Context, prefix string, tierFilter string) ([]model.DirectoryEntry, error)
	SearchObjects(ctx context.Context, query string, tierFilter string) ([]model.ObjectMeta, error)
	TouchObjectAccess(ctx context.Context, key string, accessedAt time.Time) error
	UpdateObjectTier(ctx context.Context, key string, tier model.IntelligentTier, restoreStatus model.RestoreStatus) error

	// Per-Item Access Logs
	AppendAccessLog(ctx context.Context, entry *model.AccessLogEntry) error
	ListObjectAccessLogs(ctx context.Context, key string, actionFilter string, actorFilter string, limit int) ([]model.AccessLogEntry, error)

	// In-App Access Grants & App-Managed Groups
	ListAccessGrants(ctx context.Context) ([]model.AccessGrant, error)
	UpsertAccessGrant(ctx context.Context, grant *model.AccessGrant) error
	DeleteAccessGrant(ctx context.Context, id string) error

	ListAppGroups(ctx context.Context) ([]model.AppGroup, error)
	UpsertAppGroup(ctx context.Context, group *model.AppGroup) error
	DeleteAppGroup(ctx context.Context, name string) error
	GetUserAppGroups(ctx context.Context, userEmail string) ([]string, error)

	// Service Accounts
	ListServiceAccounts(ctx context.Context) ([]model.ServiceAccount, error)
	GetServiceAccount(ctx context.Context, accountID string) (*model.ServiceAccount, error)
	UpsertServiceAccount(ctx context.Context, sa *model.ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, accountID string) error
}

// LocalStore implements MetadataStore with thread-safe in-memory indexes and JSON disk persistence.
type LocalStore struct {
	mu       sync.RWMutex
	filePath string
	state    persistedState
}

type persistedState struct {
	Objects         map[string]*model.ObjectMeta     `json:"objects"`
	Logs            map[string][]model.AccessLogEntry `json:"logs"`
	Grants          map[string]*model.AccessGrant    `json:"grants"`
	AppGroups       map[string]*model.AppGroup       `json:"app_groups"`
	ServiceAccounts map[string]*model.ServiceAccount `json:"service_accounts"`
}

// NewLocalStore initializes a LocalStore backed by a JSON file in dataDir.
func NewLocalStore(dataDir string) (*LocalStore, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	fp := filepath.Join(dataDir, "metadata-store.json")
	s := &LocalStore{
		filePath: fp,
		state: persistedState{
			Objects:         make(map[string]*model.ObjectMeta),
			Logs:            make(map[string][]model.AccessLogEntry),
			Grants:          make(map[string]*model.AccessGrant),
			AppGroups:       make(map[string]*model.AppGroup),
			ServiceAccounts: make(map[string]*model.ServiceAccount),
		},
	}
	if data, err := os.ReadFile(fp); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &s.state)
	}
	return s, nil
}

func (s *LocalStore) saveLocked() error {
	if s.filePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

func normalizeKey(k string) string {
	return strings.TrimLeft(strings.TrimSpace(k), "/")
}

func normalizePrefix(p string) string {
	p = strings.TrimLeft(strings.TrimSpace(p), "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

func parentPrefixAndName(key string) (string, string) {
	key = normalizeKey(key)
	idx := strings.LastIndex(key, "/")
	if idx == -1 {
		return "", key
	}
	return key[:idx+1], key[idx+1:]
}

func enrichMeta(m *model.ObjectMeta) *model.ObjectMeta {
	cp := *m
	if cp.StorageClass == "" {
		cp.StorageClass = "INTELLIGENT_TIERING"
	}
	if cp.RestoreStatus == "" {
		cp.RestoreStatus = model.RestoreNone
	}
	cp.IntelligentTier = cp.ComputeEffectiveTier(time.Now().UTC())
	cp.TierLabel = model.TierDisplayLabel(cp.IntelligentTier)
	return &cp
}

func (s *LocalStore) PutObjectMeta(_ context.Context, meta *model.ObjectMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normalizeKey(meta.Key)
	parent, name := parentPrefixAndName(key)
	cp := *meta
	cp.Key = key
	cp.Filename = name
	cp.ParentPrefix = parent
	if cp.StorageClass == "" {
		cp.StorageClass = "INTELLIGENT_TIERING"
	}
	if cp.IntelligentTier == "" {
		cp.IntelligentTier = model.TierFrequentAccess
	}
	if cp.RestoreStatus == "" {
		cp.RestoreStatus = model.RestoreNone
	}
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	}
	if cp.LastAccessedAt.IsZero() {
		cp.LastAccessedAt = cp.UpdatedAt
	}
	if existing, ok := s.state.Objects[key]; ok && cp.DownloadCount == 0 {
		cp.DownloadCount = existing.DownloadCount
	}
	s.state.Objects[key] = &cp
	return s.saveLocked()
}

func (s *LocalStore) GetObjectMeta(_ context.Context, key string) (*model.ObjectMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key = normalizeKey(key)
	m, ok := s.state.Objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return enrichMeta(m), nil
}

func (s *LocalStore) DeleteObjectMeta(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key = normalizeKey(key)
	if _, ok := s.state.Objects[key]; !ok {
		return ErrNotFound
	}
	delete(s.state.Objects, key)
	return s.saveLocked()
}

func (s *LocalStore) ListDirectory(_ context.Context, prefix string, tierFilter string) ([]model.DirectoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prefix = normalizePrefix(prefix)
	tierFilter = strings.ToUpper(strings.TrimSpace(tierFilter))

	dirSet := make(map[string]time.Time)
	var files []model.DirectoryEntry

	for key, rawMeta := range s.state.Objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rel := strings.TrimPrefix(key, prefix)
		if rel == "" {
			continue
		}
		meta := enrichMeta(rawMeta)
		if slashIdx := strings.Index(rel, "/"); slashIdx != -1 {
			dirName := rel[:slashIdx+1]
			if meta.UpdatedAt.After(dirSet[dirName]) {
				dirSet[dirName] = meta.UpdatedAt
			}
			continue
		}
		if tierFilter != "" && tierFilter != "ALL" && string(meta.IntelligentTier) != tierFilter {
			continue
		}
		files = append(files, model.DirectoryEntry{
			Type:            "FILE",
			Name:            rel,
			Key:             meta.Key,
			Size:            meta.Size,
			ContentType:     meta.ContentType,
			StorageClass:    meta.StorageClass,
			IntelligentTier: meta.IntelligentTier,
			TierLabel:       meta.TierLabel,
			RestoreStatus:   meta.RestoreStatus,
			SHA256:          meta.SHA256,
			SHA1:            meta.SHA1,
			HashStatus:      meta.HashStatus,
			UpdatedAt:       meta.UpdatedAt,
			LastAccessedAt:  meta.LastAccessedAt,
			DownloadCount:   meta.DownloadCount,
		})
	}

	var entries []model.DirectoryEntry
	for dirName, updated := range dirSet {
		entries = append(entries, model.DirectoryEntry{
			Type:      "DIR",
			Name:      dirName,
			Key:       prefix + dirName,
			UpdatedAt: updated,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	return append(entries, files...), nil
}

func (s *LocalStore) SearchObjects(_ context.Context, query string, tierFilter string) ([]model.ObjectMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	tierFilter = strings.ToUpper(strings.TrimSpace(tierFilter))

	var results []model.ObjectMeta
	for _, rawMeta := range s.state.Objects {
		meta := enrichMeta(rawMeta)
		if tierFilter != "" && tierFilter != "ALL" && string(meta.IntelligentTier) != tierFilter {
			continue
		}
		if q == "" ||
			strings.Contains(strings.ToLower(meta.Key), q) ||
			strings.EqualFold(meta.SHA256, q) ||
			strings.HasPrefix(strings.ToLower(meta.SHA256), q) ||
			strings.EqualFold(meta.SHA1, q) ||
			strings.HasPrefix(strings.ToLower(meta.SHA1), q) {
			results = append(results, *meta)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Key < results[j].Key
	})
	return results, nil
}

func (s *LocalStore) TouchObjectAccess(_ context.Context, key string, accessedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key = normalizeKey(key)
	m, ok := s.state.Objects[key]
	if !ok {
		return ErrNotFound
	}
	m.LastAccessedAt = accessedAt.UTC()
	m.DownloadCount++
	// Synchronous S3 Intelligent-Tiering tiers (IA, AIA) automatically move back to Frequent Access (FA) on read
	if m.IntelligentTier != model.TierArchiveAccess && m.IntelligentTier != model.TierDeepArchiveAccess {
		m.IntelligentTier = model.TierFrequentAccess
	}
	return s.saveLocked()
}

func (s *LocalStore) UpdateObjectTier(_ context.Context, key string, tier model.IntelligentTier, restoreStatus model.RestoreStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key = normalizeKey(key)
	m, ok := s.state.Objects[key]
	if !ok {
		return ErrNotFound
	}
	if tier != "" {
		m.IntelligentTier = tier
	}
	if restoreStatus != "" {
		m.RestoreStatus = restoreStatus
		if restoreStatus == model.RestoreRestored {
			m.IntelligentTier = model.TierFrequentAccess
			m.LastAccessedAt = time.Now().UTC()
			exp := time.Now().UTC().Add(7 * 24 * time.Hour)
			m.RestoreExpiry = &exp
		}
	}
	return s.saveLocked()
}

func (s *LocalStore) AppendAccessLog(_ context.Context, entry *model.AccessLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normalizeKey(entry.ObjectKey)
	cp := *entry
	cp.ObjectKey = key
	if cp.Timestamp.IsZero() {
		cp.Timestamp = time.Now().UTC()
	}
	if cp.ID == "" {
		cp.ID = fmt.Sprintf("req_%d", cp.Timestamp.UnixNano())
	}
	s.state.Logs[key] = append([]model.AccessLogEntry{cp}, s.state.Logs[key]...)
	// Keep up to 500 most recent logs per item in local mode
	if len(s.state.Logs[key]) > 500 {
		s.state.Logs[key] = s.state.Logs[key][:500]
	}
	return s.saveLocked()
}

func (s *LocalStore) ListObjectAccessLogs(_ context.Context, key string, actionFilter string, actorFilter string, limit int) ([]model.AccessLogEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key = normalizeKey(key)
	actionFilter = strings.ToUpper(strings.TrimSpace(actionFilter))
	actorFilter = strings.ToLower(strings.TrimSpace(actorFilter))
	if limit <= 0 {
		limit = 100
	}

	raw := s.state.Logs[key]
	var out []model.AccessLogEntry
	for _, entry := range raw {
		if actionFilter != "" && actionFilter != "ALL" && string(entry.Action) != actionFilter {
			continue
		}
		if actorFilter != "" && actorFilter != "all" &&
			!strings.Contains(strings.ToLower(entry.PrincipalID), actorFilter) &&
			!strings.EqualFold(string(entry.PrincipalType), actorFilter) {
			continue
		}
		out = append(out, entry)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *LocalStore) ListAccessGrants(_ context.Context) ([]model.AccessGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var grants []model.AccessGrant
	for _, g := range s.state.Grants {
		grants = append(grants, *g)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].SubjectType != grants[j].SubjectType {
			return grants[i].SubjectType < grants[j].SubjectType
		}
		return grants[i].SubjectID < grants[j].SubjectID
	})
	return grants, nil
}

func (s *LocalStore) UpsertAccessGrant(_ context.Context, grant *model.AccessGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *grant
	if cp.ID == "" {
		cp.ID = fmt.Sprintf("grant_%d", time.Now().UnixNano())
	}
	if len(cp.Prefixes) == 0 {
		cp.Prefixes = []string{"*"}
	}
	cp.UpdatedAt = time.Now().UTC()
	s.state.Grants[cp.ID] = &cp
	return s.saveLocked()
}

func (s *LocalStore) DeleteAccessGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "builtin-readonly" {
		return errors.New("cannot delete built-in baseline read-only rule")
	}
	delete(s.state.Grants, id)
	return s.saveLocked()
}

func (s *LocalStore) ListAppGroups(_ context.Context) ([]model.AppGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var groups []model.AppGroup
	for _, g := range s.state.AppGroups {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Name < groups[j].Name
	})
	return groups, nil
}

func (s *LocalStore) UpsertAppGroup(_ context.Context, group *model.AppGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *group
	cp.Name = strings.TrimSpace(cp.Name)
	cp.UpdatedAt = time.Now().UTC()
	s.state.AppGroups[cp.Name] = &cp
	return s.saveLocked()
}

func (s *LocalStore) DeleteAppGroup(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.state.AppGroups, name)
	return s.saveLocked()
}

func (s *LocalStore) GetUserAppGroups(_ context.Context, userEmail string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userEmail = strings.ToLower(strings.TrimSpace(userEmail))
	if userEmail == "" {
		return nil, nil
	}
	var matched []string
	for _, g := range s.state.AppGroups {
		for _, member := range g.Members {
			if strings.EqualFold(strings.TrimSpace(member), userEmail) {
				matched = append(matched, g.Name)
				break
			}
		}
	}
	sort.Strings(matched)
	return matched, nil
}

func (s *LocalStore) ListServiceAccounts(_ context.Context) ([]model.ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var accounts []model.ServiceAccount
	for _, sa := range s.state.ServiceAccounts {
		accounts = append(accounts, *sa)
	}
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].AccountID < accounts[j].AccountID
	})
	return accounts, nil
}

func (s *LocalStore) GetServiceAccount(_ context.Context, accountID string) (*model.ServiceAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sa, ok := s.state.ServiceAccounts[accountID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *sa
	return &cp, nil
}

func (s *LocalStore) UpsertServiceAccount(_ context.Context, sa *model.ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *sa
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	s.state.ServiceAccounts[cp.AccountID] = &cp
	return s.saveLocked()
}

func (s *LocalStore) DeleteServiceAccount(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.state.ServiceAccounts, accountID)
	return s.saveLocked()
}

