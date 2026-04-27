/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{astro,html,js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        sand: {
          DEFAULT: '#FAFAFA',
          50:  '#FFFFFF',
          100: '#F3F4F6',  // hover backgrounds
          200: '#E5E7EB',  // borders
          300: '#D1D5DB',  // stronger borders
        },
        ink: {
          DEFAULT: '#111827',
          muted:   '#6B7280',
          faint:   '#9CA3AF',
        },
        accent: {
          DEFAULT: '#2563EB',
          hover:   '#1D4ED8',
          light:   '#EFF6FF',
          border:  '#BFDBFE',
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
