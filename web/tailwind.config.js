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
        brand: {
          50: '#fffbeb',
          500: '#d97706',
          600: '#b45309',
          700: '#92400e',
        }
      }
    },
  },
  plugins: [],
}
