/**
 * "Continue with Google" — the client half.
 *
 * Google Identity Services renders its own button and, when the user picks an
 * account, hands us a signed ID token. We forward that token to the server,
 * which is where the real verification happens. This file just plumbs the
 * token across; it trusts nothing on its own.
 *
 * The whole thing is a no-op unless the server says Google is configured, so
 * the pages that include it degrade cleanly to password-only.
 */
async function initGoogleSignIn(containerId) {
  let config;
  try {
    ({ google: config } = await API.get('auth.php?action=config'));
  } catch {
    return; // server unreachable — leave the password form as the only option
  }

  if (!config.enabled) return; // no client id set: the button stays hidden

  await loadGoogleScript();

  google.accounts.id.initialize({
    client_id: config.client_id,
    callback: handleCredential,
  });

  google.accounts.id.renderButton(document.getElementById(containerId), {
    theme: 'outline',
    size: 'large',
    text: 'continue_with',
    shape: 'pill',
    width: 320,
  });

  // Reveal the "or" divider now that there really is a second option.
  document.getElementById('google-block')?.classList.remove('hidden');
}

/** Hand the signed token to our server and go where it sends us. */
async function handleCredential(response) {
  try {
    const { user } = await API.post('auth.php?action=google', {
      credential: response.credential,
    });
    window.location.href = roleHome(user.role);
  } catch (error) {
    if (typeof showBanner === 'function') {
      showBanner(error.message);
    } else {
      alert(error.message);
    }
  }
}

/** Load Google Identity Services once, on demand. */
function loadGoogleScript() {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) return resolve();

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = () => reject(new Error('Could not load Google sign-in'));
    document.head.appendChild(script);
  });
}
