// Renders demo.html to docs/img/demo.gif (for the README) and
// docs/demo/demo.mp4 (to post), a frame at a time, through headless Chrome's
// DevTools protocol and ffmpeg. Nothing to install but those two and Node 22+.
//
//   node docs/demo/render.mjs            # both
//   node docs/demo/render.mjs --frames   # only the PNGs, to look at
//   node docs/demo/render.mjs --at=4,12  # those moments as PNGs
//
// CHROME names another Chrome; FPS (30) and SCALE (2) change the capture.

import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const FPS = Number(process.env.FPS || 30);
const SCALE = Number(process.env.SCALE || 2);
const W = 1280, H = 720;
const framesOnly = process.argv.includes('--frames');
const at = process.argv.find(a => a.startsWith('--at='))?.slice(5).split(',').map(Number);

const work = mkdtempSync(join(tmpdir(), 'tangent-demo-'));
const frames = join(work, 'frames');
mkdirSync(frames);
const port = 9300 + Math.floor(Math.random() * 600);
const chrome = spawn(CHROME, [
  '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${join(work, 'profile')}`,
  '--no-first-run', '--hide-scrollbars', '--allow-file-access-from-files', '--font-render-hinting=none',
  `--window-size=${W},${H}`, 'about:blank',
], { stdio: 'ignore' });

async function target() {
  for (let i = 0; i < 100; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find(t => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`Chrome did not answer on port ${port}`);
}

const ws = new WebSocket(await target());
await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = no; });
let id = 0;
const waiting = new Map(), events = [];
ws.onmessage = m => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) {
    const { ok, no } = waiting.get(msg.id);
    waiting.delete(msg.id);
    msg.error ? no(new Error(JSON.stringify(msg.error))) : ok(msg.result);
  } else if (msg.method) events.push(msg.method);
};
const send = (method, params = {}) => new Promise((ok, no) => {
  waiting.set(++id, { ok, no });
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluate = async expression => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || expression);
  return r.result.value;
};

try {
  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: SCALE, mobile: false });
  await send('Page.navigate', { url: pathToFileURL(join(here, 'demo.html')).href + '?t=0' });
  while (!events.includes('Page.loadEventFired')) await new Promise(r => setTimeout(r, 50));
  await evaluate('document.fonts.ready.then(() => Promise.all([...document.images].map(i => i.decode())))');
  const duration = await evaluate('window.DURATION');
  const times = at || Array.from({ length: Math.round(duration * FPS) }, (_, i) => i / FPS);
  const count = times.length;
  for (let i = 0; i < count; i++) {
    await evaluate(`render(${times[i]})`);
    const { data } = await send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: W, height: H, scale: 1 } });
    writeFileSync(join(frames, `f${String(i).padStart(5, '0')}.png`), Buffer.from(data, 'base64'));
    if (i % FPS === 0) process.stdout.write(`\rframe ${i}/${count}`);
  }
  process.stdout.write(`\rframe ${count}/${count}\n`);
} finally {
  ws.close();
  chrome.kill();
}

if (framesOnly || at) {
  console.log(`frames in ${frames}`);
  process.exit(0);
}

const input = ['-y', '-loglevel', 'error', '-framerate', String(FPS), '-i', join(frames, 'f%05d.png')];
const mp4 = join(here, 'demo.mp4');
execFileSync('ffmpeg', [...input,
  '-vf', 'scale=1920:1080:flags=lanczos,format=yuv420p',
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-tune', 'stillimage', '-movflags', '+faststart', mp4], { stdio: 'inherit' });
const gif = join(root, 'docs', 'img', 'demo.gif');
execFileSync('ffmpeg', [...input,
  '-vf', 'fps=15,scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff:max_colors=192[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle',
  '-loop', '0', gif], { stdio: 'inherit' });
rmSync(work, { recursive: true, force: true });
console.log(`wrote ${gif}\nwrote ${mp4}`);
