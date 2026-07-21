/**
 * The Union Bank of Africa palette, in one place.
 *
 * Loaded straight after the Tailwind CDN on every page, so a colour is never
 * redefined per-page. Deep forest green and gold — a bank's colours, not a
 * dashboard template's.
 */
tailwind.config = {
  theme: {
    extend: {
      fontFamily: {
        display: ['Fraunces', 'Georgia', 'serif'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        forest: {
          50: '#f0f7f4',
          100: '#dbeee5',
          200: '#b9ddcd',
          300: '#8ec7ad',
          600: '#1f6f5c',
          700: '#155445',
          800: '#124436',
          900: '#0f382d',
        },
        gold: {
          50: '#fdf8ee',
          100: '#f8ebd0',
          400: '#d9a441',
          500: '#c58b25',
          600: '#a67018',
        },
        ink: '#1a1a18',
      },
    },
  },
};
