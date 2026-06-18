/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        'ids-bg':      '#0f1117',
        'ids-card':    '#1a1d27',
        'ids-card2':   '#20253a',
        'ids-border':  '#2a2d3e',
        'ids-safe':    '#1D9E75',
        'ids-danger':  '#E24B4A',
        'ids-warn':    '#F59E0B',
        'ids-orange':  '#F97316',
        'ids-text':    '#E5E7EB',
        'ids-sub':     '#9CA3AF',
        'ids-muted':   '#6B7280',
      },
      fontFamily: {
        sans: [
          'Inter', '-apple-system', 'BlinkMacSystemFont',
          '"Segoe UI"', 'Roboto', 'Helvetica', 'Arial', 'sans-serif',
        ],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
}
