package main

import "net/http"

func registerRoutes(mux *http.ServeMux, client *http.Client) {
	auth := func(h http.Handler) http.Handler {
		return authMiddleware(client, h)
	}
	admin := func(h http.Handler) http.Handler {
		return authMiddleware(client, requireRole("admin", h))
	}

	// ── Auth (public) ─────────────────────────────────────────────────────────
	mux.HandleFunc("GET /auth/login", handleAuthLogin)
	mux.HandleFunc("POST /auth/token", handleAuthToken)
	mux.HandleFunc("POST /auth/refresh", handleAuthRefresh)

	// ── Public ────────────────────────────────────────────────────────────────
	mux.HandleFunc("GET /health", handleHealth)

	// ── Authenticated — permission checks happen inside each handler ──────────
	mux.Handle("GET /api/me", auth(http.HandlerFunc(handleMe)))
	mux.Handle("GET /api/scope-introspect", auth(http.HandlerFunc(handleScopeIntrospect)))

	// Videos
	mux.Handle("GET /api/videos", auth(http.HandlerFunc(handleListVideos)))
	mux.Handle("GET /api/videos/{id}", auth(http.HandlerFunc(handleGetVideo)))
	mux.Handle("POST /api/videos", auth(http.HandlerFunc(handleUploadVideo)))
	mux.Handle("PUT /api/videos/{id}", auth(http.HandlerFunc(handleUpdateVideo)))
	mux.Handle("DELETE /api/videos/{id}", auth(http.HandlerFunc(handleDeleteVideo)))

	// Channels
	mux.Handle("GET /api/channels", auth(http.HandlerFunc(handleListChannels)))
	mux.Handle("GET /api/channels/{id}", auth(http.HandlerFunc(handleGetChannel)))
	mux.Handle("POST /api/channels", auth(http.HandlerFunc(handleCreateChannel)))
	mux.Handle("PUT /api/channels/{id}", auth(http.HandlerFunc(handleUpdateChannel)))
	mux.Handle("DELETE /api/channels/{id}", auth(http.HandlerFunc(handleDeleteChannel)))

	// Playlists
	mux.Handle("GET /api/playlists", auth(http.HandlerFunc(handleListPlaylists)))
	mux.Handle("GET /api/playlists/{id}", auth(http.HandlerFunc(handleGetPlaylist)))
	mux.Handle("POST /api/playlists", auth(http.HandlerFunc(handleCreatePlaylist)))
	mux.Handle("PUT /api/playlists/{id}", auth(http.HandlerFunc(handleUpdatePlaylist)))
	mux.Handle("DELETE /api/playlists/{id}", auth(http.HandlerFunc(handleDeletePlaylist)))

	// Comments
	mux.Handle("GET /api/comments", auth(http.HandlerFunc(handleListComments)))
	mux.Handle("GET /api/comments/{id}", auth(http.HandlerFunc(handleGetComment)))
	mux.Handle("POST /api/comments", auth(http.HandlerFunc(handleCreateComment)))
	mux.Handle("DELETE /api/comments/{id}", auth(http.HandlerFunc(handleDeleteComment)))

	// Admin
	mux.Handle("GET /api/admin/users", admin(http.HandlerFunc(handleAdminUsers)))
	mux.Handle("DELETE /api/admin/users/{id}", admin(http.HandlerFunc(handleDeleteAdminUser)))

	// Debug — remove in production
	mux.Handle("GET /api/debug/perms", auth(http.HandlerFunc(handleDebugPerms)))
	mux.Handle("POST /api/debug/grant", auth(http.HandlerFunc(handleDebugGrant)))
	mux.Handle("DELETE /api/debug/revoke", auth(http.HandlerFunc(handleDebugRevoke)))
}
