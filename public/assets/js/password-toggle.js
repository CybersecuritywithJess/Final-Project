/**
 * Adds a "Show / Hide" toggle to every password field on the page.
 *
 * Drop this script onto any page and it just works: it wraps each password
 * input in a positioned container and drops a small text button on the right.
 * A MutationObserver picks up inputs that appear later (e.g. the admin's
 * "create user" form, which is rendered after load), so nothing has to call in.
 */
(function () {
  function enhance(root) {
    const inputs = (root || document).querySelectorAll(
      'input[type="password"]:not([data-pw-ready])'
    );

    inputs.forEach((input) => {
      input.dataset.pwReady = '1';

      // Wrap the input so the button can sit inside its right edge.
      const wrap = document.createElement('div');
      wrap.className = 'relative';
      input.parentNode.insertBefore(wrap, input);
      wrap.appendChild(input);

      // Leave room so the typed text never slides under the button.
      input.classList.add('pr-16');

      const toggle = document.createElement('button');
      toggle.type = 'button';           // never submit the form
      toggle.tabIndex = -1;             // keep it out of tab order
      toggle.setAttribute('aria-label', 'Show password');
      toggle.textContent = 'Show';
      toggle.className =
        'absolute inset-y-0 right-0 flex items-center pr-3 text-xs font-semibold ' +
        'text-stone-500 transition hover:text-forest-800';

      toggle.addEventListener('click', () => {
        const reveal = input.type === 'password';
        input.type = reveal ? 'text' : 'password';
        toggle.textContent = reveal ? 'Hide' : 'Show';
        toggle.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
      });

      wrap.appendChild(toggle);
    });
  }

  document.addEventListener('DOMContentLoaded', () => enhance());

  // Catch password fields added to the DOM after the initial render.
  new MutationObserver(() => enhance()).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
})();
