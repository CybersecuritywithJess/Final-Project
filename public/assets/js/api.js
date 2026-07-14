/**
 * The only place in the frontend that talks to the server.
 *
 * Session cookies travel automatically, so there is no token to juggle. A 401
 * anywhere means the session lapsed — we bounce to the login page rather than
 * letting the UI render half-empty.
 */
const API = {
  async request(endpoint, { method = 'GET', body = null, params = {} } = {}) {
    const url = new URL(`/api/${endpoint}`, window.location.origin);
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== null && value !== undefined) {
        url.searchParams.set(key, value);
      }
    }

    const options = { method, headers: {}, credentials: 'same-origin' };

    // Lets the demo simulate a login from another country / IP without one.
    const demo = JSON.parse(sessionStorage.getItem('demo_context') || 'null');
    if (demo) {
      options.headers['X-Demo-Country'] = demo.country;
      options.headers['X-Demo-City'] = demo.city;
      options.headers['X-Demo-Ip'] = demo.ip;
    }

    if (body) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);

    if (response.status === 401 && !endpoint.startsWith('auth.php?action=login')) {
      window.location.href = '/login.html?expired=1';
      throw new Error('Session expired');
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.error || `Request failed (${response.status})`);
    }

    return data;
  },

  get: (endpoint, params) => API.request(endpoint, { params }),
  post: (endpoint, body, params) => API.request(endpoint, { method: 'POST', body, params }),
  patch: (endpoint, body, params) => API.request(endpoint, { method: 'PATCH', body, params }),
  del: (endpoint, params) => API.request(endpoint, { method: 'DELETE', params }),

  // -- auth ----------------------------------------------------------------
  login: (username, password) =>
    API.post('auth.php?action=login', { username, password }),
  register: (data) => API.post('auth.php?action=register', data),
  logout: () => API.post('auth.php?action=logout'),
  me: () => API.get('auth.php?action=me'),

  /**
   * "Am I signed in?" — for public pages, where being signed out is normal and
   * must NOT bounce the visitor to the login screen. Resolves to the user, or
   * null. Deliberately bypasses request()'s 401 redirect.
   */
  async whoami() {
    const response = await fetch('/api/auth.php?action=me', { credentials: 'same-origin' });
    if (!response.ok) return null;
    const { user } = await response.json();
    return user ?? null;
  },
};
