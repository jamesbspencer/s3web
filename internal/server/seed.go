package server

import (
	"bytes"
	"context"
	"time"

	"s3web/internal/auth"
	"s3web/internal/model"
)

func (s *Server) seedBootstrapData(ctx context.Context) error {
	grants, err := s.store.ListAccessGrants(ctx)
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		// 1. Default Baseline Rule: All Authenticated SSO Users are Read-Only
		_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
			ID:          "builtin-readonly",
			Description: "Default Baseline: All authenticated SSO users have Read-Only access",
			SubjectType: model.SubjectBuiltin,
			SubjectID:   "authenticated-users",
			Prefixes:    []string{"*"},
			CanRead:     true,
			CanUpload:   false,
			CanDelete:   false,
			IsAdmin:     false,
			UpdatedBy:   "system",
		})

		// 2. Platform Admins OIDC Group -> Full In-App Admin + Upload + Delete
		_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
			ID:          "grant-oidc-platform-admins",
			Description: "Platform Admins OIDC Group (Full Admin, Upload & Delete)",
			SubjectType: model.SubjectOIDCGroup,
			SubjectID:   s.cfg.BootstrapAdminOIDCGroup,
			Prefixes:    []string{"*"},
			CanRead:     true,
			CanUpload:   true,
			CanDelete:   true,
			IsAdmin:     true,
			UpdatedBy:   "system",
		})

		// 3. Release Engineering OIDC Group -> Upload allowed on linux/* and isos/*
		_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
			ID:          "grant-oidc-release-eng",
			Description: "Release Engineering OIDC Group (Upload ISOs & Linux Images)",
			SubjectType: model.SubjectOIDCGroup,
			SubjectID:   "release-engineering",
			Prefixes:    []string{"linux/*", "isos/*"},
			CanRead:     true,
			CanUpload:   true,
			CanDelete:   false,
			IsAdmin:     false,
			UpdatedBy:   "system",
		})

		// 4. App-Managed Group "iso-curators" -> Upload & Delete allowed across bucket
		_ = s.store.UpsertAppGroup(ctx, &model.AppGroup{
			Name:        "iso-curators",
			Description: "In-App Storage Curators with Upload & Delete privileges",
			Members:     []string{"curator@example.com", s.cfg.BootstrapAdminEmail},
			UpdatedBy:   "system",
		})
		_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
			ID:          "grant-appgroup-curators",
			Description: "In-App Group: ISO Curators (Upload & Delete)",
			SubjectType: model.SubjectAppGroup,
			SubjectID:   "iso-curators",
			Prefixes:    []string{"*"},
			CanRead:     true,
			CanUpload:   true,
			CanDelete:   true,
			IsAdmin:     false,
			UpdatedBy:   "system",
		})

		// 5. GitHub Actions OIDC Workflow Grant -> Secretless JWT Upload to isos/* and linux/*
		_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
			ID:          "grant-github-iso-builder",
			Description: "GitHub Actions OIDC Workflow (my-org/iso-builder on main branch)",
			SubjectType: model.SubjectGitHubWorkflow,
			SubjectID:   "repo:my-org/iso-builder:ref:refs/heads/main",
			Prefixes:    []string{"isos/*", "linux/*"},
			CanRead:     true,
			CanUpload:   true,
			CanDelete:   false,
			IsAdmin:     false,
			UpdatedBy:   "system",
		})

		// 6. Sonatype Nexus Proxy Service Account -> Read-Only across entire bucket
		nexusHash, err := auth.HashSecret(s.cfg.BootstrapNexusAccountKey)
		if err == nil {
			_ = s.store.UpsertServiceAccount(ctx, &model.ServiceAccount{
				AccountID:   s.cfg.BootstrapNexusAccountID,
				Name:        "Sonatype Nexus Raw Proxy Service Account",
				Description: "Used by Sonatype Nexus Raw (Proxy) Repository over Private VPC",
				SecretHash:  nexusHash,
				CreatedBy:   "system",
			})
			_ = s.store.UpsertAccessGrant(ctx, &model.AccessGrant{
				ID:          "grant-sa-" + s.cfg.BootstrapNexusAccountID,
				Description: "Sonatype Nexus Raw Proxy Read-Only Grant",
				SubjectType: model.SubjectServiceAccount,
				SubjectID:   s.cfg.BootstrapNexusAccountID,
				Prefixes:    []string{"*"},
				CanRead:     true,
				CanUpload:   false,
				CanDelete:   false,
				IsAdmin:     false,
				UpdatedBy:   "system",
			})
		}
	}

	// Seed representative ISO & compressed archive artifacts across Intelligent-Tiering tiers if empty
	existing, err := s.store.SearchObjects(ctx, "", "")
	if err == nil && len(existing) == 0 {
		now := time.Now().UTC()
		samples := []struct {
			key          string
			content      string
			tier         model.IntelligentTier
			uploadedBy   string
			updatedAgo   time.Duration
			accessedAgo  time.Duration
			downloads    int64
		}{
			{
				key:         "linux/ubuntu/24.04/ubuntu-24.04.1-live-server-amd64.iso",
				content:     "ISO9660-IMAGE-HEADER:ubuntu-24.04.1-live-server-amd64-build-20261105\n",
				tier:        model.TierFrequentAccess,
				uploadedBy:  "gh:my-org/iso-builder@main#9821",
				updatedAgo:  48 * time.Hour,
				accessedAgo: 15 * time.Minute,
				downloads:   18,
			},
			{
				key:         "linux/ubuntu/24.04/ubuntu-24.04.1-netboot-amd64.tar.zst",
				content:     "ZSTD-ARCHIVE-HEADER:ubuntu-24.04.1-netboot-amd64\n",
				tier:        model.TierFrequentAccess,
				uploadedBy:  "gh:my-org/iso-builder@main#9821",
				updatedAgo:  48 * time.Hour,
				accessedAgo: 2 * time.Hour,
				downloads:   7,
			},
			{
				key:         "linux/rhel/9.4/rhel-9.4-x86_64-dvd.iso",
				content:     "ISO9660-IMAGE-HEADER:rhel-9.4-x86_64-dvd-enterprise\n",
				tier:        model.TierInfrequentAccess,
				uploadedBy:  "rel-eng@example.com",
				updatedAgo:  60 * 24 * time.Hour,
				accessedAgo: 45 * 24 * time.Hour,
				downloads:   11,
			},
			{
				key:         "linux/debian/12/debian-12.7.0-amd64-netinst.iso",
				content:     "ISO9660-IMAGE-HEADER:debian-12.7.0-amd64-netinst\n",
				tier:        model.TierArchiveInstantAccess,
				uploadedBy:  "rel-eng@example.com",
				updatedAgo:  130 * 24 * time.Hour,
				accessedAgo: 105 * 24 * time.Hour,
				downloads:   4,
			},
			{
				key:         "isos/legacy/centos-7.9-2009-x86_64-minimal.iso",
				content:     "ISO9660-IMAGE-HEADER:centos-7.9-2009-x86_64-minimal-archive\n",
				tier:        model.TierArchiveAccess,
				uploadedBy:  "curator@example.com",
				updatedAgo:  240 * 24 * time.Hour,
				accessedAgo: 210 * 24 * time.Hour,
				downloads:   2,
			},
		}

		for _, item := range samples {
			putRes, err := s.storage.PutStream(ctx, item.key, bytes.NewReader([]byte(item.content)), detectContentType(item.key))
			if err != nil {
				continue
			}
			meta := &model.ObjectMeta{
				Key:             putRes.Key,
				Size:            putRes.Size,
				ContentType:     detectContentType(item.key),
				StorageClass:    "INTELLIGENT_TIERING",
				IntelligentTier: item.tier,
				RestoreStatus:   model.RestoreNone,
				SHA256:          putRes.SHA256,
				SHA1:            putRes.SHA1,
				HashStatus:      model.HashReady,
				S3ETag:          putRes.ETag,
				UploadedBy:      item.uploadedBy,
				UpdatedAt:       now.Add(-item.updatedAgo),
				LastAccessedAt:  now.Add(-item.accessedAgo),
				DownloadCount:   item.downloads,
			}
			_ = s.store.PutObjectMeta(ctx, meta)

			// Seed initial per-item access history for each object
			_ = s.store.AppendAccessLog(ctx, &model.AccessLogEntry{
				ObjectKey:     item.key,
				Timestamp:     now.Add(-item.updatedAgo),
				Action:        model.ActionUpload,
				PrincipalType: model.PrincipalGitHubWorkflow,
				PrincipalID:   item.uploadedBy,
				ClientIP:      "10.24.8.41",
				UserAgent:     "GitHub-Actions-Runner/2.319.1 (vpc-private-subnet)",
				BytesSent:     putRes.Size,
				StatusCode:    201,
				DurationMs:    1240,
			})
			_ = s.store.AppendAccessLog(ctx, &model.AccessLogEntry{
				ObjectKey:     item.key,
				Timestamp:     now.Add(-item.accessedAgo),
				Action:        model.ActionDownload,
				PrincipalType: model.PrincipalServiceAccount,
				PrincipalID:   s.cfg.BootstrapNexusAccountID,
				ClientIP:      "10.24.4.19",
				UserAgent:     "Nexus/3.70.1-02 (OSS; Linux; amd64; RawProxy)",
				BytesSent:     putRes.Size,
				StatusCode:    200,
				DurationMs:    310,
			})
		}
	}

	return nil
}

