package main

import "net/http"

func registerRoutes(mux *http.ServeMux, client *http.Client) {
	// auth      — valid JWT only (public-ish, e.g. health, debug)
	// user      — valid JWT + platform role "user" assigned in Zitadel
	// admin     — valid JWT + platform role "admin" assigned in Zitadel
	auth := func(h http.Handler) http.Handler {
		return authMiddleware(client, h)
	}
	user := func(h http.Handler) http.Handler {
		return authMiddleware(client, requireRole("user", h))
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

	// ── Authenticated — platform role "user" required, resource checks inside ──
	mux.Handle("GET /api/me", user(http.HandlerFunc(handleMe)))
	mux.Handle("GET /api/scope-introspect", user(http.HandlerFunc(handleScopeIntrospect)))

	// Videos
	mux.Handle("GET /api/videos", user(http.HandlerFunc(handleListVideos)))
	mux.Handle("GET /api/videos/{id}", user(http.HandlerFunc(handleGetVideo)))
	mux.Handle("POST /api/videos", user(http.HandlerFunc(handleUploadVideo)))
	mux.Handle("PUT /api/videos/{id}", user(http.HandlerFunc(handleUpdateVideo)))
	mux.Handle("DELETE /api/videos/{id}", user(http.HandlerFunc(handleDeleteVideo)))

	// Channels
	mux.Handle("GET /api/channels", user(http.HandlerFunc(handleListChannels)))
	mux.Handle("GET /api/channels/{id}", user(http.HandlerFunc(handleGetChannel)))
	mux.Handle("POST /api/channels", user(http.HandlerFunc(handleCreateChannel)))
	mux.Handle("PUT /api/channels/{id}", user(http.HandlerFunc(handleUpdateChannel)))
	mux.Handle("DELETE /api/channels/{id}", user(http.HandlerFunc(handleDeleteChannel)))

	// Playlists
	mux.Handle("GET /api/playlists", user(http.HandlerFunc(handleListPlaylists)))
	mux.Handle("GET /api/playlists/{id}", user(http.HandlerFunc(handleGetPlaylist)))
	mux.Handle("POST /api/playlists", user(http.HandlerFunc(handleCreatePlaylist)))
	mux.Handle("PUT /api/playlists/{id}", user(http.HandlerFunc(handleUpdatePlaylist)))
	mux.Handle("DELETE /api/playlists/{id}", user(http.HandlerFunc(handleDeletePlaylist)))

	// Comments
	mux.Handle("GET /api/comments", user(http.HandlerFunc(handleListComments)))
	mux.Handle("GET /api/comments/{id}", user(http.HandlerFunc(handleGetComment)))
	mux.Handle("POST /api/comments", user(http.HandlerFunc(handleCreateComment)))
	mux.Handle("DELETE /api/comments/{id}", user(http.HandlerFunc(handleDeleteComment)))

	// Admin
	mux.Handle("GET /api/admin/users", admin(http.HandlerFunc(handleAdminUsers)))
	mux.Handle("DELETE /api/admin/users/{id}", admin(http.HandlerFunc(handleDeleteAdminUser)))

	// Debug — remove in production
	mux.Handle("GET /api/debug/perms", auth(http.HandlerFunc(handleDebugPerms)))
	mux.Handle("POST /api/debug/grant", auth(http.HandlerFunc(handleDebugGrant)))
	mux.Handle("DELETE /api/debug/revoke", auth(http.HandlerFunc(handleDebugRevoke)))
}
