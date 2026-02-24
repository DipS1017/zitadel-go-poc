package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// =============================================================================
// Response helpers
// =============================================================================

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// =============================================================================
// Health / Me / Scope introspect
// =============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sub":      user.Sub,
		"name":     user.Name,
		"email":    user.Email,
		"username": user.Username,
		"org_id":   user.OrgID,
		"org_name": user.OrgName,
		"scopes":   user.Scopes,
		"roles":    user.Roles,
	})
}

func handleScopeIntrospect(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scopes": user.Scopes,
		"roles":  user.Roles,
	})
}

// =============================================================================
// Mock data store
// =============================================================================

var mockVideos = map[string]map[string]interface{}{
	"v1": {"id": "v1", "title": "Go Concurrency Patterns", "channel_id": "c1"},
	"v2": {"id": "v2", "title": "Zitadel Auth Deep Dive", "channel_id": "c1"},
}

var mockChannels = map[string]map[string]interface{}{
	"c1": {"id": "c1", "name": "Go Academy"},
}

var mockPlaylists = map[string]map[string]interface{}{
	"p1": {"id": "p1", "title": "Backend Essentials", "video_ids": []string{"v1", "v2"}},
}

var mockComments = map[string]map[string]interface{}{
	"cm1": {"id": "cm1", "video_id": "v1", "body": "Great explanation!"},
}

// =============================================================================
// Videos
// =============================================================================

func handleListVideos(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var result []map[string]interface{}
	for id, v := range mockVideos {
		if canAccess(user.Sub, "video", id, "viewer") {
			result = append(result, v)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func handleGetVideo(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "video", id, "viewer") {
		writeError(w, http.StatusForbidden, "no access to this video")
		return
	}
	v, ok := mockVideos[id]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("video %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func handleUploadVideo(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	newID := fmt.Sprintf("v%d", len(mockVideos)+1)
	mockVideos[newID] = map[string]interface{}{"id": newID, "title": "New Video"}
	grantAccess(user.Sub, "video", newID, "creator")
	writeJSON(w, http.StatusCreated, map[string]string{"id": newID, "status": "uploaded"})
}

func handleUpdateVideo(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "video", id, "creator") {
		writeError(w, http.StatusForbidden, "no access to update this video")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeleteVideo(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "video", id, "creator") {
		writeError(w, http.StatusForbidden, "only the owner can delete this video")
		return
	}
	delete(mockVideos, id)
	revokeAccess(user.Sub, "video", id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Channels
// =============================================================================

func handleListChannels(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var result []map[string]interface{}
	for id, c := range mockChannels {
		if canAccess(user.Sub, "channel", id, "viewer") {
			result = append(result, c)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func handleGetChannel(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "channel", id, "viewer") {
		writeError(w, http.StatusForbidden, "no access to this channel")
		return
	}
	c, ok := mockChannels[id]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("channel %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	newID := fmt.Sprintf("c%d", len(mockChannels)+1)
	mockChannels[newID] = map[string]interface{}{"id": newID, "name": "New Channel"}
	grantAccess(user.Sub, "channel", newID, "creator")
	writeJSON(w, http.StatusCreated, map[string]string{"id": newID, "status": "created"})
}

func handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "channel", id, "creator") {
		writeError(w, http.StatusForbidden, "no access to update this channel")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "channel", id, "creator") {
		writeError(w, http.StatusForbidden, "only the owner can delete this channel")
		return
	}
	delete(mockChannels, id)
	revokeAccess(user.Sub, "channel", id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Playlists
// =============================================================================

func handleListPlaylists(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var result []map[string]interface{}
	for id, p := range mockPlaylists {
		if canAccess(user.Sub, "playlist", id, "viewer") {
			result = append(result, p)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func handleGetPlaylist(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "playlist", id, "viewer") {
		writeError(w, http.StatusForbidden, "no access to this playlist")
		return
	}
	p, ok := mockPlaylists[id]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("playlist %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func handleCreatePlaylist(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	newID := fmt.Sprintf("p%d", len(mockPlaylists)+1)
	mockPlaylists[newID] = map[string]interface{}{"id": newID, "title": "New Playlist"}
	grantAccess(user.Sub, "playlist", newID, "creator")
	writeJSON(w, http.StatusCreated, map[string]string{"id": newID, "status": "created"})
}

func handleUpdatePlaylist(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "playlist", id, "creator") {
		writeError(w, http.StatusForbidden, "no access to update this playlist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeletePlaylist(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "playlist", id, "creator") {
		writeError(w, http.StatusForbidden, "only the owner can delete this playlist")
		return
	}
	delete(mockPlaylists, id)
	revokeAccess(user.Sub, "playlist", id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Comments
// =============================================================================

func handleListComments(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var result []map[string]interface{}
	for id, c := range mockComments {
		if canAccess(user.Sub, "comment", id, "viewer") {
			result = append(result, c)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func handleGetComment(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "comment", id, "viewer") {
		writeError(w, http.StatusForbidden, "no access to this comment")
		return
	}
	c, ok := mockComments[id]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("comment %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func handleCreateComment(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	newID := fmt.Sprintf("cm%d", len(mockComments)+1)
	mockComments[newID] = map[string]interface{}{"id": newID, "body": "New Comment"}
	grantAccess(user.Sub, "comment", newID, "creator")
	writeJSON(w, http.StatusCreated, map[string]string{"id": newID, "status": "created"})
}

func handleDeleteComment(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	id := r.PathValue("id")
	if !canAccess(user.Sub, "comment", id, "creator") {
		writeError(w, http.StatusForbidden, "no access to delete this comment")
		return
	}
	delete(mockComments, id)
	revokeAccess(user.Sub, "comment", id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Debug — inspect and edit the current user's resource permissions
// These routes exist only for testing. Remove in production.
// =============================================================================

// GET /api/debug/perms — list every resource role the current user holds
func handleDebugPerms(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	result := map[string]string{}
	for k, role := range permStore {
		// key format: "userID|resourceType|resourceID"
		parts := splitKey(k)
		if parts[0] == user.Sub {
			result[parts[1]+"/"+parts[2]] = role
		}
	}
	writeJSON(w, http.StatusOK, result)
}

type grantRequest struct {
	ResourceType string `json:"resource_type"` // "video" | "channel" | "playlist" | "comment"
	ResourceID   string `json:"resource_id"`
	Role         string `json:"role"` // "admin" | "creator" | "viewer"
}

// POST /api/debug/grant — give the current user a role on a resource
func handleDebugGrant(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var req grantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ResourceType == "" || req.ResourceID == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "body must include resource_type, resource_id, role")
		return
	}
	if _, ok := roleRank[req.Role]; !ok {
		writeError(w, http.StatusBadRequest, "role must be owner, editor, or viewer")
		return
	}
	grantAccess(user.Sub, req.ResourceType, req.ResourceID, req.Role)
	writeJSON(w, http.StatusOK, map[string]string{
		"user":          user.Sub,
		"resource_type": req.ResourceType,
		"resource_id":   req.ResourceID,
		"role":          req.Role,
		"status":        "granted",
	})
}

// DELETE /api/debug/revoke — remove the current user's role on a resource
func handleDebugRevoke(w http.ResponseWriter, r *http.Request) {
	user, _ := getUserFromContext(r)
	var req struct {
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ResourceType == "" || req.ResourceID == "" {
		writeError(w, http.StatusBadRequest, "body must include resource_type and resource_id")
		return
	}
	revokeAccess(user.Sub, req.ResourceType, req.ResourceID)
	writeJSON(w, http.StatusOK, map[string]string{
		"resource_type": req.ResourceType,
		"resource_id":   req.ResourceID,
		"status":        "revoked",
	})
}

// splitKey splits a permStore key ("a|b|c") into parts.
func splitKey(key string) []string {
	parts := make([]string, 3)
	i, j := 0, 0
	for n := 0; n < 2; n++ {
		j = i
		for j < len(key) && key[j] != '|' {
			j++
		}
		parts[n] = key[i:j]
		i = j + 1
	}
	parts[2] = key[i:]
	return parts
}

// =============================================================================
// Admin
// =============================================================================

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]interface{}{
		{"id": "u1", "username": "alice", "role": "creator"},
		{"id": "u2", "username": "bob", "role": "viewer"},
	})
}

func handleDeleteAdminUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}
