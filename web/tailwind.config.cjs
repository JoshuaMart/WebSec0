/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{astro,html,js,ts,jsx,tsx,mdx}'],
  safelist: [
    // Dynamic grade classes returned from Alpine JS functions
    'text-accent', 'bg-accent', 'bg-accent-light', 'border-accent-border',
    'text-amber-600', 'bg-amber-50', 'bg-amber-500', 'border-amber-200',
    'text-red-600',   'bg-red-50',   'bg-red-500',   'border-red-200',
    'bg-sand-100', 'border-sand-200', 'bg-sand-300',
  ],
  theme: {
    extend: {
      colors: {
        sand: {
          DEFAULT: '#fdfcf9',
          50:  '#ffffff',
          100: '#f4f3ef',  // hover backgrounds
          200: '#e8e5df',  // borders
          300: '#d4d0c9',  // stronger borders
        },
        ink: {
          DEFAULT: '#111827',
          muted:   '#6B7280',
          faint:   '#9CA3AF',
        },
        accent: {
          DEFAULT: '#4e9a52',
          hover:   '#3d7a40',
          light:   '#dbf3db',
          border:  '#b8e8b9',
        },
        severity: {
          critical: '#DC2626',
          high:     '#EA580C',
          medium:   '#D97706',
          low:      '#2563EB',
          info:     '#9CA3AF',
          pass:     '#16A34A',
        },
      },
      fontFamily: {
        sans: ['"Inter Variable"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'Menlo', 'monospace'],
      },
      boxShadow: {
        input: '0 1px 3px 0 rgba(17, 24, 39, 0.06)',
      },
    },
  },
  plugins: [],
};
