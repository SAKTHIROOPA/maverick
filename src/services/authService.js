/**
 * MAVERICK SOC Authentication Service
 * Manages demo authentication, credential validation, session persistence, and logout.
 */

export const DEMO_CREDENTIALS = {
  email: 'admin@example.com',
  username: 'admin',
  password: 'admin123',
  displayName: 'Analyst SIH-01',
  role: 'SOC Lead Tier-3',
  clearanceLevel: 'TOP-SECRET // SIH-2026',
  avatarInitials: 'MK'
};

const AUTH_STORAGE_KEY = 'maverick_auth_session';

/**
 * Validates login credentials and creates an authenticated session.
 * @param {string} identifier - Email or username
 * @param {string} password - Password
 * @param {boolean} rememberMe - Whether to persist session across browser restarts
 * @returns {{ success: boolean, error?: string, user?: object }}
 */
export function authenticateUser(identifier, password, rememberMe = true) {
  const cleanId = (identifier || '').trim().toLowerCase();
  const cleanPass = (password || '').trim();

  if (!cleanId) {
    return { success: false, error: 'Email or username is required.' };
  }

  if (!cleanPass) {
    return { success: false, error: 'Password is required.' };
  }

  const isIdentifierValid =
    cleanId === DEMO_CREDENTIALS.email.toLowerCase() ||
    cleanId === DEMO_CREDENTIALS.username.toLowerCase();

  const isPasswordValid = cleanPass === DEMO_CREDENTIALS.password;

  if (isIdentifierValid && isPasswordValid) {
    const session = {
      isAuthenticated: true,
      rememberMe: Boolean(rememberMe),
      loginTimestamp: new Date().toISOString(),
      user: {
        email: DEMO_CREDENTIALS.email,
        username: DEMO_CREDENTIALS.username,
        name: DEMO_CREDENTIALS.displayName,
        role: DEMO_CREDENTIALS.role,
        clearance: DEMO_CREDENTIALS.clearanceLevel,
        initials: DEMO_CREDENTIALS.avatarInitials
      }
    };

    const storage = rememberMe ? localStorage : sessionStorage;
    
    // Clear opposite storage to prevent stale session conflicts
    if (rememberMe) {
      sessionStorage.removeItem(AUTH_STORAGE_KEY);
    } else {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    }

    try {
      storage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
    } catch (e) {
      console.warn('Storage quota error when saving auth session:', e);
    }

    return { success: true, user: session.user };
  }

  return { 
    success: false, 
    error: 'Invalid email or password. Use demo account: admin@example.com / admin123' 
  };
}

/**
 * Checks if a valid authenticated session exists in storage.
 * @returns {object|null} The active session object or null
 */
export function getActiveSession() {
  try {
    const localData = localStorage.getItem(AUTH_STORAGE_KEY);
    if (localData) {
      const parsed = JSON.parse(localData);
      if (parsed && parsed.isAuthenticated) return parsed;
    }

    const sessionData = sessionStorage.getItem(AUTH_STORAGE_KEY);
    if (sessionData) {
      const parsed = JSON.parse(sessionData);
      if (parsed && parsed.isAuthenticated) return parsed;
    }
  } catch (e) {
    console.error('Error reading auth session from storage:', e);
  }

  return null;
}

/**
 * Returns true if the user is currently logged in.
 * @returns {boolean}
 */
export function checkIsAuthenticated() {
  return Boolean(getActiveSession());
}

/**
 * Terminates the active session and clears persistent storage.
 */
export function terminateSession() {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
    sessionStorage.removeItem(AUTH_STORAGE_KEY);
  } catch (e) {
    console.warn('Error clearing auth session:', e);
  }
}
