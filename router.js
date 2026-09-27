// Lightweight prefetch-only router (no SPA swapping)
(function() {
  'use strict';

  const prefetchDelay = 100;

  function isInternal(url) {
    const a = document.createElement('a');
    a.href = url;
    return a.hostname === window.location.hostname || !a.hostname;
  }

  function prefetchPage(url) {
    if (!document.querySelector(`link[rel="prefetch"][href="${url}"]`)) {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.href = url;
      document.head.appendChild(link);
    }
  }

  // Prefetch on hover only, let browser handle all navigation normally
  document.addEventListener('mouseenter', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href');
    if (href && isInternal(href) && !href.startsWith('#') && (href.endsWith('.html') || href.startsWith('/'))) {
      const timeout = setTimeout(() => prefetchPage(href), prefetchDelay);
      link.addEventListener('mouseleave', () => clearTimeout(timeout), { once: true });
    }
  }, true);

})();

