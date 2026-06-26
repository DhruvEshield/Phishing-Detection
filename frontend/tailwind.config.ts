/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // PhishSkill palette: blue/emerald/rose/slate — no indigo, no gradients on data
        brand: {
          blue: '#2563EB',
          emerald: '#059669',
          rose: '#E11D48',
          slate: '#334155',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
