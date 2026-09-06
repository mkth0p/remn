// Applies the stored theme before the first paint (kept out of index.html so the page carries no inline script).
try {
  var t = localStorage.getItem('remn-theme')
  if (t !== 'dark' && t !== 'light') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  document.documentElement.dataset.theme = t
  var m = document.querySelector('meta[name="color-scheme"]')
  if (m) m.setAttribute('content', t)
} catch (e) {}
