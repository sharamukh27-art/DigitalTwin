// ============================================
// SHARANYAVERSE — behavior layer
// ============================================

document.addEventListener('DOMContentLoaded', () => {
  initBootSequence();
  initCustomCursor();
  initNavbar();
  initTypingEffect();
  initStatCounters();
  initScrollReveal();
  initSkillBars();
});

/* ---------- Boot sequence ---------- */
function initBootSequence() {
  const boot = document.getElementById('bootSequence');
  if (!boot) return;
  document.body.style.overflow = 'hidden';
  setTimeout(() => {
    boot.classList.add('hidden');
    document.body.style.overflow = '';
  }, 2100);
}

/* ---------- Custom cursor (desktop only) ---------- */
function initCustomCursor() {
  const cursor = document.getElementById('customCursor');
  if (!cursor || window.matchMedia('(max-width: 900px)').matches) return;

  window.addEventListener('mousemove', (e) => {
    cursor.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
  });

  const interactive = 'a, button, .skill-card, .project-card, .metric-card, .contact-card';
  document.querySelectorAll(interactive).forEach((el) => {
    el.addEventListener('mouseenter', () => cursor.classList.add('active'));
    el.addEventListener('mouseleave', () => cursor.classList.remove('active'));
  });
}

/* ---------- Navbar: hamburger + active link on scroll ---------- */
function initNavbar() {
  const hamburger = document.getElementById('hamburger');
  const navMenu = document.getElementById('nav-menu');

  if (hamburger && navMenu) {
    hamburger.addEventListener('click', () => navMenu.classList.toggle('active'));
    navMenu.querySelectorAll('a').forEach((link) =>
      link.addEventListener('click', () => navMenu.classList.remove('active'))
    );
  }
}

/* ---------- Typing / role rotator ---------- */
function initTypingEffect() {
  const el = document.getElementById('typingText');
  if (!el) return;

  const roles = ['SOFTWARE DEVELOPER', 'AI ENGINEER', 'ROBOTIC SYSTEMS DEV'];
  let roleIndex = 0;
  let charIndex = roles[0].length;
  let deleting = false;

  function tick() {
    const current = roles[roleIndex];
    if (!deleting) {
      charIndex++;
      if (charIndex > current.length) {
        deleting = true;
        setTimeout(tick, 1800);
        return;
      }
    } else {
      charIndex--;
      if (charIndex < 0) {
        deleting = false;
        roleIndex = (roleIndex + 1) % roles.length;
        charIndex = 0;
      }
    }
    el.textContent = current.slice(0, charIndex);
    setTimeout(tick, deleting ? 35 : 60);
  }

  el.textContent = roles[0];
  setTimeout(tick, 2200);
}

/* ---------- Stat counters ---------- */
function initStatCounters() {
  const stats = document.querySelectorAll('.stat-value[data-target]');
  if (!stats.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      const target = parseInt(el.dataset.target, 10);
      const duration = 1200;
      const start = performance.now();

      function update(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(update);
      }
      requestAnimationFrame(update);
      observer.unobserve(el);
    });
  }, { threshold: 0.5 });

  stats.forEach((el) => observer.observe(el));
}

/* ---------- Skill bar fill on view ---------- */
function initSkillBars() {
  const bars = document.querySelectorAll('.skill-progress[data-progress]');
  if (!bars.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      const el = entry.target;
      el.style.width = el.dataset.progress + '%';
      observer.unobserve(el);
    });
  }, { threshold: 0.4 });

  bars.forEach((el) => observer.observe(el));
}

/* ---------- Scroll reveal for section content ---------- */
function initScrollReveal() {
  const targets = document.querySelectorAll(
    '.about-main-panel, .metric-card, .skill-card, .project-card, .contact-card'
  );
  targets.forEach((el) => el.classList.add('reveal'));

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, i) => {
      if (!entry.isIntersecting) return;
      setTimeout(() => entry.target.classList.add('in-view'), (i % 4) * 80);
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.15 });

  targets.forEach((el) => observer.observe(el));
}