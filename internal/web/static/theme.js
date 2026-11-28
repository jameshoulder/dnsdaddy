// Apply the saved theme before paint. A same-origin file works with the
// dashboard's script-src 'self' policy without allowing inline scripts.
(function () {
  try {
    var theme = localStorage.getItem('dnsdaddy.theme');
    if (theme !== 'light' && theme !== 'dark') theme = 'dark';
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
  } catch (e) {
    document.documentElement.dataset.theme = 'dark';
  }
})();
