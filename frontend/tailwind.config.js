/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0A0D12',
        surface: '#12161F',
        raised: '#181D28',
        border: '#232938',
        borderLight: '#2E3648',
        text: '#E7EAF0',
        muted: '#8891A3',
        dim: '#5B6376',
        accent: '#4FD1C5',
        accentDim: '#2E6E68',
        critical: '#F0465A',
        high: '#F5943D',
        medium: '#F2C94C',
        low: '#6B93C4',
        safe: '#3DD68C', // new: quantum-safe (PQC level 3-5) — CBOM tab only
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        sans: ['"Inter"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
