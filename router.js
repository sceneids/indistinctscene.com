// Lightweight prefetch-only router (no SPA swapping)
(function() {
  'use strict';

  const prefetchDelay = 100;

  function getInternalPageUrl(url) {
    let parsedUrl;

    try {
      parsedUrl = new URL(url, window.location.href);
    } catch {
      return null;
    }

    if (parsedUrl.origin !== window.location.origin || !['http:', 'https:'].includes(parsedUrl.protocol)) {
      return null;
    }

    return parsedUrl;
  }

  function prefetchPage(url) {
    const alreadyPrefetched = Array.from(document.querySelectorAll('link[rel="prefetch"]'))
      .some((link) => link.href === url.href);

    if (!alreadyPrefetched) {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.href = url.href;
      document.head.appendChild(link);
    }
  }

  // Prefetch on hover only, let browser handle all navigation normally
  document.addEventListener('mouseenter', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href');
    const pageUrl = href ? getInternalPageUrl(href) : null;
    if (pageUrl && !href.startsWith('#') && pageUrl.pathname.endsWith('.html')) {
      const timeout = setTimeout(() => prefetchPage(pageUrl), prefetchDelay);
      link.addEventListener('mouseleave', () => clearTimeout(timeout), { once: true });
    }
  }, true);

})();
