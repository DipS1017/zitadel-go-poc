package main

import "net/http"

// registerRoutes wires all application routes onto mux.
// cfg is read from the global var — not passed as a parameter.
func registerRoutes(mux *http.ServeMux, client *http.Client) {
	auth := func(h http.Handler) http.Handler {
		return authMiddleware(client, h)
	}

	scopeOrRole := func(scope string, roles []string, h http.Handler) http.Handler {
		return requireScopeOrRole(scope, roles, h)
	}

	roleOnly := func(role string, h http.Handler) http.Handler {
		return requireRole(role, h)
	}

	allRoles      := []string{"viewer", "editor", "owner", "admin"}
	writeRoles    := []string{"editor", "owner", "admin"}
	deleteRoles   := []string{"owner", "admin"}
	commentDelete := []string{"editor", "owner", "admin"}

	// ── Auth (public — no token required) ────────────────────────────────────
	mux.HandleFunc("GET /auth/login", handleAuthLogin)
	mux.HandleFunc("POST /auth/token", handleAuthToken)
	mux.HandleFunc("POST /auth/refresh", handleAuthRefresh)

	// ── Public ────────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /health", handleHealth)

	// ── Authenticated (any valid token) ───────────────────────────────────────
	mux.Handle("GET /api/me",
		auth(http.HandlerFunc(handleMe)))

	mux.Handle("GET /api/scope-introspect",
		auth(http.HandlerFunc(handleScopeIntrospect)))

	// ── Videos ────────────────────────────────────────────────────────────────
	mux.Handle("GET /api/videos",
		auth(scopeOrRole("videos:view", allRoles,
			http.HandlerFunc(handleListVideos))))

	mux.Handle("GET /api/videos/{id}",
		auth(scopeOrRole("videos:read", allRoles,
			http.HandlerFunc(handleGetVideo))))

	mux.Handle("POST /api/videos",
		auth(scopeOrRole("videos:write", writeRoles,
			http.HandlerFunc(handleUploadVideo))))

	mux.Handle("PUT /api/videos/{id}",
		auth(scopeOrRole("videos:write", writeRoles,
			http.HandlerFunc(handleUpdateVideo))))

	mux.Handle("DELETE /api/videos/{id}",
		auth(scopeOrRole("videos:delete", deleteRoles,
			http.HandlerFunc(handleDeleteVideo))))

	// ── Channels ──────────────────────────────────────────────────────────────
	mux.Handle("GET /api/channels",
		auth(scopeOrRole("channels:view", allRoles,
			http.HandlerFunc(handleListChannels))))

	mux.Handle("GET /api/channels/{id}",
		auth(scopeOrRole("channels:read", allRoles,
			http.HandlerFunc(handleGetChannel))))

	mux.Handle("POST /api/channels",
		auth(scopeOrRole("channels:write", writeRoles,
			http.HandlerFunc(handleCreateChannel))))

	mux.Handle("PUT /api/channels/{id}",
		auth(scopeOrRole("channels:write", writeRoles,
			http.HandlerFunc(handleUpdateChannel))))

	mux.Handle("DELETE /api/channels/{id}",
		auth(scopeOrRole("channels:delete", deleteRoles,
			http.HandlerFunc(handleDeleteChannel))))

	// ── Playlists ─────────────────────────────────────────────────────────────
	mux.Handle("GET /api/playlists",
		auth(scopeOrRole("playlists:view", allRoles,
			http.HandlerFunc(handleListPlaylists))))

	mux.Handle("GET /api/playlists/{id}",
		auth(scopeOrRole("playlists:read", allRoles,
			http.HandlerFunc(handleGetPlaylist))))

	mux.Handle("POST /api/playlists",
		auth(scopeOrRole("playlists:write", writeRoles,
			http.HandlerFunc(handleCreatePlaylist))))

	mux.Handle("PUT /api/playlists/{id}",
		auth(scopeOrRole("playlists:write", writeRoles,
			http.HandlerFunc(handleUpdatePlaylist))))

	mux.Handle("DELETE /api/playlists/{id}",
		auth(scopeOrRole("playlists:delete", deleteRoles,
			http.HandlerFunc(handleDeletePlaylist))))

	// ── Comments ──────────────────────────────────────────────────────────────
	mux.Handle("GET /api/comments",
		auth(scopeOrRole("comments:view", allRoles,
			http.HandlerFunc(handleListComments))))

	mux.Handle("GET /api/comments/{id}",
		auth(scopeOrRole("comments:read", allRoles,
			http.HandlerFunc(handleGetComment))))

	mux.Handle("POST /api/comments",
		auth(scopeOrRole("comments:write", allRoles,
			http.HandlerFunc(handleCreateComment))))

	mux.Handle("DELETE /api/comments/{id}",
		auth(scopeOrRole("comments:delete", commentDelete,
			http.HandlerFunc(handleDeleteComment))))

	// ── Admin (role-only) ─────────────────────────────────────────────────────
	mux.Handle("GET /api/admin/users",
		auth(roleOnly("admin",
			http.HandlerFunc(handleAdminUsers))))

	mux.Handle("DELETE /api/admin/users/{id}",
		auth(roleOnly("admin",
			http.HandlerFunc(handleDeleteAdminUser))))
}
