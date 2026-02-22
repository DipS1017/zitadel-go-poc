import { useEffect, useState } from 'react'

function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    return JSON.parse(atob(token.split('.')[1]))
  } catch {
    return null
  }
}

// =============================================================================
// API tester
// =============================================================================

type EndpointResult = {
  status: number | null
  body: unknown
  loading: boolean
  error: string | null
}

type Endpoint = {
  label: string
  method: string
  path: string
  group: string
}

const ENDPOINTS: Endpoint[] = [
  // Auth / info
  { group: 'Auth',     label: 'GET /health',              method: 'GET',    path: '/health' },
  { group: 'Auth',     label: 'GET /api/me',               method: 'GET',    path: '/api/me' },
  { group: 'Auth',     label: 'GET /api/scope-introspect', method: 'GET',    path: '/api/scope-introspect' },
  // Videos
  { group: 'Videos',   label: 'GET    /api/videos',        method: 'GET',    path: '/api/videos' },
  { group: 'Videos',   label: 'GET    /api/videos/v1',     method: 'GET',    path: '/api/videos/v1' },
  { group: 'Videos',   label: 'POST   /api/videos',        method: 'POST',   path: '/api/videos' },
  { group: 'Videos',   label: 'PUT    /api/videos/v1',     method: 'PUT',    path: '/api/videos/v1' },
  { group: 'Videos',   label: 'DELETE /api/videos/v1',     method: 'DELETE', path: '/api/videos/v1' },
  // Channels
  { group: 'Channels', label: 'GET    /api/channels',      method: 'GET',    path: '/api/channels' },
  { group: 'Channels', label: 'GET    /api/channels/c1',   method: 'GET',    path: '/api/channels/c1' },
  { group: 'Channels', label: 'POST   /api/channels',      method: 'POST',   path: '/api/channels' },
  { group: 'Channels', label: 'PUT    /api/channels/c1',   method: 'PUT',    path: '/api/channels/c1' },
  { group: 'Channels', label: 'DELETE /api/channels/c1',   method: 'DELETE', path: '/api/channels/c1' },
  // Playlists
  { group: 'Playlists',label: 'GET    /api/playlists',     method: 'GET',    path: '/api/playlists' },
  { group: 'Playlists',label: 'GET    /api/playlists/p1',  method: 'GET',    path: '/api/playlists/p1' },
  { group: 'Playlists',label: 'POST   /api/playlists',     method: 'POST',   path: '/api/playlists' },
  { group: 'Playlists',label: 'PUT    /api/playlists/p1',  method: 'PUT',    path: '/api/playlists/p1' },
  { group: 'Playlists',label: 'DELETE /api/playlists/p1',  method: 'DELETE', path: '/api/playlists/p1' },
  // Comments
  { group: 'Comments', label: 'GET    /api/comments',      method: 'GET',    path: '/api/comments' },
  { group: 'Comments', label: 'GET    /api/comments/cm1',  method: 'GET',    path: '/api/comments/cm1' },
  { group: 'Comments', label: 'POST   /api/comments',      method: 'POST',   path: '/api/comments' },
  { group: 'Comments', label: 'DELETE /api/comments/cm1',  method: 'DELETE', path: '/api/comments/cm1' },
  // Admin
  { group: 'Admin',    label: 'GET    /api/admin/users',   method: 'GET',    path: '/api/admin/users' },
  { group: 'Admin',    label: 'DELETE /api/admin/users/u1',method: 'DELETE', path: '/api/admin/users/u1' },
]

const METHOD_COLOR: Record<string, string> = {
  GET:    '#4ade80',
  POST:   '#60a5fa',
  PUT:    '#fbbf24',
  DELETE: '#f87171',
}

function EndpointRow({ ep, token }: { ep: Endpoint; token: string | null }) {
  const [result, setResult] = useState<EndpointResult>({ status: null, body: null, loading: false, error: null })

  async function hit() {
    setResult({ status: null, body: null, loading: true, error: null })
    try {
      const res = await fetch(ep.path, {
        method: ep.method,
        headers: token
          ? { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
          : { 'Content-Type': 'application/json' },
      })
      let body: unknown
      try { body = await res.json() } catch { body = null }
      setResult({ status: res.status, body, loading: false, error: null })
    } catch (e) {
      setResult({ status: null, body: null, loading: false, error: String(e) })
    }
  }

  const { status, body, loading, error } = result
  const statusColor = status == null ? '#888' : status < 300 ? '#4ade80' : status < 400 ? '#fbbf24' : '#f87171'

  return (
    <div style={styles.row}>
      <div style={styles.rowLeft}>
        <span style={{ ...styles.methodBadge, color: METHOD_COLOR[ep.method] ?? '#fff' }}>
          {ep.method}
        </span>
        <span style={styles.path}>{ep.path}</span>
      </div>

      <button style={styles.hitBtn} onClick={hit} disabled={loading}>
        {loading ? '...' : 'Hit'}
      </button>

      <div style={styles.resultBox}>
        {status != null && (
          <span style={{ color: statusColor, fontWeight: 700, marginRight: 8 }}>{status}</span>
        )}
        {error && <span style={{ color: '#f87171' }}>{error}</span>}
        {body != null && (
          <span style={styles.bodyText}>{JSON.stringify(body)}</span>
        )}
      </div>
    </div>
  )
}

function ApiTester({ token }: { token: string | null }) {
  const groups = [...new Set(ENDPOINTS.map(e => e.group))]

  return (
    <div style={styles.tester}>
      {groups.map(group => (
        <div key={group} style={styles.group}>
          <div style={styles.groupLabel}>{group}</div>
          {ENDPOINTS.filter(e => e.group === group).map(ep => (
            <EndpointRow key={ep.label} ep={ep} token={token} />
          ))}
        </div>
      ))}
    </div>
  )
}

// =============================================================================
// Callback page
// =============================================================================
function Callback() {
  const [status, setStatus] = useState('Completing login...')

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code  = params.get('code')
    const state = params.get('state')
    const error = params.get('error')

    if (error) {
      setStatus(`Zitadel error: ${error} — ${params.get('error_description') ?? ''}`)
      return
    }
    if (!code) {
      setStatus(`No code received. URL: ${window.location.href}`)
      return
    }

    fetch('/auth/token', {
      method:      'POST',
      headers:     { 'Content-Type': 'application/json' },
      credentials: 'include',
      body:        JSON.stringify({ code, state }),
    })
      .then(r => r.json())
      .then(data => {
        if (data.access_token) {
          localStorage.setItem('access_token',  data.access_token)
          localStorage.setItem('refresh_token', data.refresh_token ?? '')
          window.location.href = '/'
        } else {
          setStatus('Login failed — ' + (data.error ?? 'unknown error'))
        }
      })
      .catch(() => setStatus('Login failed — network error'))
  }, [])

  return <p style={{ padding: 32 }}>{status}</p>
}

// =============================================================================
// Home page
// =============================================================================
function Home() {
  const token = localStorage.getItem('access_token')
  const user  = token ? decodeJWT(token) : null

  function logout() {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    window.location.href = '/'
  }

  return (
    <div style={styles.page}>
      <div style={styles.header}>
        <span style={styles.title}>API Tester</span>
        {user ? (
          <div style={styles.userRow}>
            <span style={styles.userName}>{String(user.name ?? user.email ?? user.sub)}</span>
            <button style={styles.logoutBtn} onClick={logout}>Logout</button>
          </div>
        ) : (
          <button style={styles.loginBtn} onClick={() => { window.location.href = '/auth/login' }}>
            Login / Register
          </button>
        )}
      </div>

      {!user && (
        <p style={styles.hint}>Log in to send authenticated requests. Public endpoints work without a token.</p>
      )}

      <ApiTester token={token} />
    </div>
  )
}

// =============================================================================
// Root router
// =============================================================================
export default function App() {
  if (window.location.pathname === '/auth/callback') return <Callback />
  return <Home />
}

// =============================================================================
// Inline styles
// =============================================================================
const styles: Record<string, React.CSSProperties> = {
  page: {
    minHeight: '100vh',
    width: '100%',
    background: '#111',
    color: '#e5e5e5',
    fontFamily: 'monospace',
    boxSizing: 'border-box',
    padding: '0 0 48px',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px 24px',
    borderBottom: '1px solid #222',
    background: '#1a1a1a',
    position: 'sticky',
    top: 0,
    zIndex: 10,
  },
  title: {
    fontSize: 18,
    fontWeight: 700,
    color: '#fff',
  },
  userRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
  },
  userName: {
    color: '#aaa',
    fontSize: 13,
  },
  loginBtn: {
    background: '#646cff',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    padding: '6px 16px',
    cursor: 'pointer',
    fontSize: 13,
  },
  logoutBtn: {
    background: '#2a2a2a',
    color: '#aaa',
    border: '1px solid #333',
    borderRadius: 6,
    padding: '4px 12px',
    cursor: 'pointer',
    fontSize: 12,
  },
  hint: {
    padding: '12px 24px',
    color: '#666',
    fontSize: 13,
    margin: 0,
  },
  tester: {
    padding: '16px 24px',
    display: 'flex',
    flexDirection: 'column',
    gap: 24,
  },
  group: {
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  groupLabel: {
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: 2,
    color: '#555',
    marginBottom: 4,
    paddingLeft: 4,
  },
  row: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    background: '#1a1a1a',
    border: '1px solid #222',
    borderRadius: 6,
    padding: '8px 12px',
    flexWrap: 'wrap',
  },
  rowLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    minWidth: 280,
    flex: '0 0 auto',
  },
  methodBadge: {
    fontSize: 11,
    fontWeight: 700,
    width: 50,
    display: 'inline-block',
  },
  path: {
    fontSize: 13,
    color: '#ccc',
  },
  hitBtn: {
    background: '#2a2a2a',
    color: '#fff',
    border: '1px solid #444',
    borderRadius: 4,
    padding: '4px 14px',
    cursor: 'pointer',
    fontSize: 12,
    flex: '0 0 auto',
  },
  resultBox: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    minWidth: 0,
    overflow: 'hidden',
  },
  bodyText: {
    fontSize: 12,
    color: '#888',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
}
