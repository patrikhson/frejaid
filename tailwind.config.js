/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./internal/templates/**/*.html",
    "./static/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        gold: {
          400: '#c9a84c',
          500: '#b8960a',
        },
      },
    },
  },
  plugins: [],
}
