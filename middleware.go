package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

// =============================================================================
// Logging middleware
// =============================================================================

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			log.Printf("OPTIONS %s 204", r.URL.Path)
			return
		}

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d", r.Method, r.URL.Path, rw.status)
	})
}

// =============================================================================
// Auth middleware
// =============================================================================

// authMiddleware validates the Bearer token by verifying its JWT signature
// against Zitadel's JWKS endpoint (keys are cached locally).
// On success it stores a userContext in the request context.
func authMiddleware(client *http.Client, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken, err := extractBearerToken(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		validateCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		claims, err := validateJWT(validateCtx, client, rawToken)
		if err != nil {
			log.Printf("JWT validation error: %v", err)
			writeError(w, http.StatusUnauthorized, "token validation failed")
			return
		}

		if !audienceMatches([]string(claims.Audience), cfg.requiredAudience) {
			writeError(w, http.StatusForbidden, "token audience mismatch")
			return
		}

		uc := userContext{
			Sub:      claims.Subject,
			Name:     claims.Name,
			Email:    claims.Email,
			Username: claims.Username,
			Scopes:   parseScopes(claims.Scope),
			Roles:    extractRoleNames(claims.Roles),
			OrgID:    claims.OrgID,
			OrgName:  claims.OrgName,
		}

		ctx := context.WithValue(r.Context(), userContextKey, uc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =============================================================================
// Authorization middleware
// =============================================================================

func requireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if !hasScope(user.Scopes, scope) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("required scope: %s", scope))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if !hasRole(user.Roles, role) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("required role: %s", role))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireScopeOrRole(scope string, roles []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := getUserFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if hasScope(user.Scopes, scope) || hasAnyRole(user.Roles, roles...) {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error":          "insufficient permissions",
			"required_scope": scope,
			"required_roles": roles,
		})
	})
}
