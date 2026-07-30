/* SmartHunt visual effects.
 *
 * Everything here is decoration and must never get in the way of the scan:
 * each effect is cheap, pauses when the tab is hidden, and switches off
 * entirely under prefers-reduced-motion.
 */
'use strict';

const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ── matrix rain, behind everything ───────────────────────── */
function matrixRain() {
  if (REDUCED) return;
  const canvas = document.createElement('canvas');
  canvas.id = 'matrix';
  document.body.prepend(canvas);
  const ctx = canvas.getContext('2d', { alpha: true });
  const GLYPHS = 'アイウエオカキクケコサシスセソ0123456789ABCDEF<>/{}[]$#@!*';
  let columns = [], w = 0, h = 0, raf = null;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
    const count = Math.floor(w / 22);
    columns = Array.from({ length: count }, () => Math.random() * -h);
  }

  let last = 0;
  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (now - last < 55) return;          // ~18fps is plenty and stays cheap
    last = now;
    ctx.fillStyle = 'rgba(5, 8, 7, 0.10)';
    ctx.fillRect(0, 0, w, h);
    ctx.font = '14px monospace';
    for (let i = 0; i < columns.length; i++) {
      const glyph = GLYPHS[(Math.random() * GLYPHS.length) | 0];
      const x = i * 22, y = columns[i];
      ctx.fillStyle = Math.random() > 0.97 ? 'rgba(200,255,220,.55)' : 'rgba(0,255,156,.16)';
      ctx.fillText(glyph, x, y);
      columns[i] = y > h + Math.random() * 400 ? 0 : y + 22;
    }
  }

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); raf = null; }
    else if (!raf) raf = requestAnimationFrame(frame);
  });
  resize();
  raf = requestAnimationFrame(frame);
}

/* ── boot sequence ────────────────────────────────────────── */
const BOOT_LINES = [
  'initialising smarthunt kernel',
  'loading tool arsenal',
  'arming owasp top 10 module',
  'calibrating evidence gate',
  'ready — awaiting target',
];

function bootSequence(toolCount) {
  const host = document.getElementById('bootLog');
  if (!host) return;
  if (REDUCED) { host.textContent = BOOT_LINES[BOOT_LINES.length - 1]; return; }
  let i = 0;
  const tick = () => {
    if (i >= BOOT_LINES.length) { host.classList.add('boot-done'); return; }
    const line = BOOT_LINES[i] === 'loading tool arsenal' && toolCount
      ? `loading tool arsenal — ${toolCount} detected` : BOOT_LINES[i];
    host.textContent = `[${String(i + 1).padStart(2, '0')}] ${line}`;
    i += 1;
    setTimeout(tick, 260);
  };
  tick();
}

/* ── count-up for the dashboard readouts ──────────────────── */
function countUp(el, target, duration = 620) {
  const value = Number(target);
  if (REDUCED || !Number.isFinite(value) || value === 0) {
    el.textContent = target;
    return;
  }
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / duration);
    // ease-out cubic: fast then settling, which reads as "counting up"
    el.textContent = Math.round(value * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
    else el.textContent = target;
  }
  requestAnimationFrame(step);
}

function animateCards(root) {
  root.querySelectorAll('.card .num').forEach((el) => {
    countUp(el, el.dataset.value ?? el.textContent);
  });
}

/* ── typing effect for a headline ─────────────────────────── */
function typeInto(el, text, speed = 18) {
  if (REDUCED) { el.textContent = text; return; }
  el.textContent = '';
  let i = 0;
  (function tick() {
    el.textContent = text.slice(0, i);
    if (i++ <= text.length) setTimeout(tick, speed);
  })();
}

/* ── glitch burst, used when a critical finding lands ─────── */
function glitch(el, ms = 420) {
  if (REDUCED || !el) return;
  el.classList.add('glitching');
  setTimeout(() => el.classList.remove('glitching'), ms);
}

window.SmartHuntFX = { matrixRain, bootSequence, countUp, animateCards, typeInto,
                       glitch, REDUCED };
