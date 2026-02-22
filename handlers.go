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
// Health
// =============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// =============================================================================
// Me / Scope introspection
// =============================================================================

func handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
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
	user, ok := getUserFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scopes": user.Scopes,
		"roles":  user.Roles,
	})
}

// =============================================================================
// Mock data
// =============================================================================

var mockVideos = []map[string]interface{}{
	{"id": "v1", "title": "Go Concurrency Patterns", "channel_id": "c1"},
	{"id": "v2", "title": "Zitadel Auth Deep Dive", "channel_id": "c1"},
}

var mockChannels = []map[string]interface{}{
	{"id": "c1", "name": "Go Academy", "owner": "user123"},
}

var mockPlaylists = []map[string]interface{}{
	{"id": "p1", "title": "Backend Essentials", "video_ids": []string{"v1", "v2"}},
}

var mockComments = []map[string]interface{}{
	{"id": "cm1", "video_id": "v1", "body": "Great explanation!", "author": "user456"},
}

// =============================================================================
// Videos
// =============================================================================

func handleListVideos(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mockVideos)
}

func handleGetVideo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, v := range mockVideos {
		if v["id"] == id {
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("video %s not found", id))
}

func handleUploadVideo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]string{"id": "v-new", "status": "uploaded"})
}

func handleUpdateVideo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeleteVideo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Channels
// =============================================================================

func handleListChannels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mockChannels)
}

func handleGetChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, c := range mockChannels {
		if c["id"] == id {
			writeJSON(w, http.StatusOK, c)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("channel %s not found", id))
}

func handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]string{"id": "c-new", "status": "created"})
}

func handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Playlists
// =============================================================================

func handleListPlaylists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mockPlaylists)
}

func handleGetPlaylist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, p := range mockPlaylists {
		if p["id"] == id {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("playlist %s not found", id))
}

func handleCreatePlaylist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]string{"id": "p-new", "status": "created"})
}

func handleUpdatePlaylist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

func handleDeletePlaylist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Comments
// =============================================================================

func handleListComments(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, mockComments)
}

func handleGetComment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, c := range mockComments {
		if c["id"] == id {
			writeJSON(w, http.StatusOK, c)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("comment %s not found", id))
}

func handleCreateComment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]string{"id": "cm-new", "status": "created"})
}

func handleDeleteComment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}

// =============================================================================
// Admin
// =============================================================================

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []map[string]interface{}{
		{"id": "u1", "username": "alice", "roles": []string{"editor"}},
		{"id": "u2", "username": "bob", "roles": []string{"viewer"}},
	})
}

func handleDeleteAdminUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "deleted"})
}
