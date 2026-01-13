/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        yellow: '#F5D742',
        'deep-indigo': '#0A0C3A',
        navy: '#1A1446',
        'near-black': '#070910',
        graphite: '#2B2E3A',
        charcoal: '#343748',
        slate: '#F6F7FB',
        success: '#32D74B',
        error: '#F44336',
      },
    },
  },
  plugins: [],
}
