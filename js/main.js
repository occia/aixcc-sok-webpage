// Mobile TOC drawer: floating button toggles body.toc-open. Backdrop and
// link clicks close it. Esc also closes. No-op on wide viewports where the
// sidebar is fixed and the button is hidden via CSS.
(function () {
  const toggle  = document.querySelector('.toc-toggle');
  const backdrop = document.querySelector('.toc-backdrop');
  if (!toggle || !backdrop) return;

  const open  = () => { document.body.classList.add('toc-open');    toggle.setAttribute('aria-expanded', 'true');  };
  const close = () => { document.body.classList.remove('toc-open'); toggle.setAttribute('aria-expanded', 'false'); };

  toggle.addEventListener('click', () => {
    document.body.classList.contains('toc-open') ? close() : open();
  });
  backdrop.addEventListener('click', close);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  // Auto-close when user picks a section
  document.querySelectorAll('aside.sidebar nav a[href^="#"]').forEach(a => {
    a.addEventListener('click', () => {
      if (matchMedia('(max-width: 1000px)').matches) close();
    });
  });
})();

// Highlight the current section in the sidebar as the user scrolls.
(function () {
  const links = Array.from(document.querySelectorAll('aside.sidebar nav a[href^="#"]'));
  if (!links.length) return;

  const byId = new Map();
  links.forEach(a => {
    const id = a.getAttribute('href').slice(1);
    if (id) byId.set(id, a);
  });

  const sections = links
    .map(a => document.getElementById(a.getAttribute('href').slice(1)))
    .filter(Boolean);

  function setActive(id) {
    links.forEach(a => a.classList.remove('active'));
    const a = byId.get(id);
    if (a) a.classList.add('active');
  }

  const observer = new IntersectionObserver(entries => {
    // Pick the first entry that is intersecting and closest to the top.
    const visible = entries
      .filter(e => e.isIntersecting)
      .sort((a, b) => a.target.getBoundingClientRect().top - b.target.getBoundingClientRect().top);
    if (visible.length) setActive(visible[0].target.id);
  }, {
    rootMargin: '-10% 0px -70% 0px',
    threshold: 0,
  });

  sections.forEach(s => observer.observe(s));

  // Initial state: pick first section in view.
  function init() {
    const top = window.scrollY + 80;
    let current = sections[0];
    for (const s of sections) {
      if (s.offsetTop <= top) current = s;
      else break;
    }
    if (current) setActive(current.id);
  }
  init();
})();
