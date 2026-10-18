/* CampusUTA — Sprint 1: registro, aviso y consentimiento, login.
   Persistencia local (localStorage). Las contraseñas nunca se guardan en claro:
   se almacenan como PBKDF2-SHA256 con sal aleatoria por usuario. */
'use strict';

const AVISO_VERSION = '2026-10-v1';
const KEYS = { users: 'campusuta.users', session: 'campusuta.session' };
const $app = document.getElementById('app');

/* ---------- Almacenamiento ---------- */
const db = {
  users() { try { return JSON.parse(localStorage.getItem(KEYS.users)) || []; } catch { return []; } },
  save(u) { localStorage.setItem(KEYS.users, JSON.stringify(u)); },
  find(email) { return this.users().find(u => u.email === email.trim().toLowerCase()); },
  session() { try { return JSON.parse(sessionStorage.getItem(KEYS.session)); } catch { return null; } },
  setSession(s) { s ? sessionStorage.setItem(KEYS.session, JSON.stringify(s)) : sessionStorage.removeItem(KEYS.session); }
};

/* ---------- Criptografía ---------- */
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function hashPassword(pass, saltB64) {
  const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 120000 }, key, 256);
  return { salt: b64(salt), hash: b64(bits) };
}

/* ---------- Utilidades ---------- */
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const topbar = (back) => `<header class="top">${back ? '<button class="back" data-go="' + back + '" aria-label="Volver">‹</button>' : '<div class="logo">C</div>'}<div><h1>CampusUTA</h1><small>Universidad Tecnológica de Aguascalientes</small></div></header>`;
function strength(p) {
  let s = 0;
  if (p.length >= 8) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return s;
}
function setErr(form, name, msg) {
  const f = form.querySelector('[data-f="' + name + '"]');
  if (!f) return;
  f.classList.toggle('bad', !!msg);
  f.querySelector('.msg').textContent = msg || '';
}

/* ---------- Estado del flujo de registro ---------- */
let draft = { nombre: '', email: '', matricula: '', pass: '', pass2: '' };

/* ---------- Pantallas ---------- */
const views = {
  welcome() {
    return `${topbar()}<section class="screen">
      <h2>Bienvenido</h2>
      <p class="mut">Tu campus en el bolsillo. Crea una cuenta o inicia sesión para continuar.</p>
      <div class="card"><h3>Tu privacidad primero</h3><ul><li>Te mostramos el aviso de privacidad antes de guardar tus datos.</li><li>Solo recabamos lo necesario.</li><li>Puedes ejercer tus derechos ARCO desde la app.</li></ul></div>
      <div style="flex:1"></div>
      <button class="btn gold" data-go="registro">Crear cuenta</button>
      <button class="btn ghost" data-go="login">Ya tengo cuenta</button></section>`;
  },

  registro() {
    return `${topbar('welcome')}<section class="screen">
      <div class="steps"><i class="on"></i><i></i><i></i></div>
      <h2>Crear cuenta</h2><p class="mut">Paso 1 de 2 · Tus datos</p>
      <form id="f-reg" novalidate autocomplete="off">
        <div class="field" data-f="nombre"><label for="nombre">Nombre completo</label><input id="nombre" type="text" value="${esc(draft.nombre)}" autocomplete="name"><div class="msg"></div></div>
        <div class="field" data-f="email" style="margin-top:12px"><label for="email">Correo electrónico</label><input id="email" type="email" value="${esc(draft.email)}" autocomplete="email"><div class="msg"></div></div>
        <div class="field" data-f="matricula" style="margin-top:12px"><label for="matricula">Matrícula</label><input id="matricula" type="text" inputmode="numeric" maxlength="8" value="${esc(draft.matricula)}"><div class="msg"></div></div>
        <div class="field" data-f="pass" style="margin-top:12px"><label for="pass">Contraseña</label><input id="pass" type="password" value="${esc(draft.pass)}" autocomplete="new-password"><div class="strength" style="margin-top:8px"><i id="bar"></i></div><p class="mut" style="margin-top:4px">Mínimo 8 caracteres, con mayúscula, minúscula y número.</p><div class="msg"></div></div>
        <div class="field" data-f="pass2" style="margin-top:12px"><label for="pass2">Confirmar contraseña</label><input id="pass2" type="password" value="${esc(draft.pass2)}" autocomplete="new-password"><div class="msg"></div></div>
        <button class="btn" type="submit" style="margin-top:18px">Continuar al aviso de privacidad</button>
      </form>
      <button class="link center" data-go="login">¿Ya tienes cuenta? Inicia sesión</button></section>`;
  },

  aviso() {
    return `${topbar('registro')}<section class="screen">
      <div class="steps"><i class="on"></i><i class="on"></i><i></i></div>
      <h2>Aviso de privacidad</h2><p class="mut">Paso 2 de 2 · Léelo y otorga tu consentimiento (versión ${AVISO_VERSION})</p>
      <div class="card notice" id="notice" tabindex="0">
        <h3>1. Responsable</h3><p>CampusUTA, proyecto académico de la Universidad Tecnológica de Aguascalientes, grupo IDGS 10-C, es responsable del tratamiento de tus datos personales.</p>
        <h3>2. Datos que recabamos</h3><p>Nombre completo, correo electrónico, matrícula y contraseña (almacenada de forma cifrada irreversible). No recabamos datos personales sensibles.</p>
        <h3>3. Finalidades necesarias</h3><p>Crear y administrar tu cuenta, autenticarte y darte acceso a los servicios del campus.</p>
        <h3>4. Finalidades opcionales</h3><p>Enviarte avisos y novedades del campus. Puedes negarte sin perder acceso a la app.</p>
        <h3>5. Transferencias</h3><p>No transferimos tus datos a terceros.</p>
        <h3>6. Derechos ARCO</h3><p>Puedes solicitar el acceso, la rectificación, la cancelación y la oposición al tratamiento de tus datos desde la sección «Mi privacidad» dentro de la app.</p>
        <h3>7. Medidas de seguridad</h3><p>Aplicamos medidas administrativas, técnicas y físicas razonables. Tu contraseña se guarda con PBKDF2-SHA256 y sal única.</p>
        <h3>8. Cambios al aviso</h3><p>Cualquier cambio se te informará dentro de la app y se solicitará de nuevo tu consentimiento si altera las finalidades.</p>
      </div>
      <label class="chk req"><input type="checkbox" id="c-aviso"><span><b>*</b> He leído y comprendo el aviso de privacidad.</span></label>
      <label class="chk req"><input type="checkbox" id="c-datos"><span><b>*</b> Otorgo mi consentimiento para el tratamiento de mis datos para las finalidades necesarias.</span></label>
      <label class="chk"><input type="checkbox" id="c-mkt"><span>Acepto recibir avisos y novedades del campus (opcional).</span></label>
      <div id="aviso-err" class="banner err" hidden>Debes aceptar el aviso y el consentimiento necesario para crear tu cuenta.</div>
      <button class="btn gold" id="btn-crear" disabled>Aceptar y crear cuenta</button>
      <button class="btn ghost" data-go="rechazo">No acepto</button></section>`;
  },

  rechazo() {
    return `${topbar()}<section class="screen">
      <h2>Registro cancelado</h2>
      <p>Sin tu consentimiento no podemos crear la cuenta. No guardamos ninguno de los datos que escribiste.</p>
      <div style="flex:1"></div>
      <button class="btn" data-go="welcome">Volver al inicio</button></section>`;
  },

  login(opts = {}) {
    return `${topbar('welcome')}<section class="screen">
      <h2>Iniciar sesión</h2>
      ${opts.ok ? '<div class="banner ok">Cuenta creada correctamente. Ya puedes iniciar sesión.</div>' : ''}
      <form id="f-login" novalidate>
        <div id="login-err" class="banner err" hidden style="margin-bottom:12px"></div>
        <div class="field" data-f="email"><label for="l-email">Correo electrónico</label><input id="l-email" type="email" value="${esc(opts.email || '')}" autocomplete="email"><div class="msg"></div></div>
        <div class="field" data-f="pass" style="margin-top:12px"><label for="l-pass">Contraseña</label><input id="l-pass" type="password" autocomplete="current-password"><div class="msg"></div></div>
        <button class="btn" type="submit" style="margin-top:18px">Entrar</button>
      </form>
      <button class="link center" data-go="registro">¿No tienes cuenta? Regístrate</button></section>`;
  },

  home() {
    const s = db.session();
    const u = s && db.users().find(x => x.id === s.id);
    if (!u) return views.login();
    return `${topbar()}<section class="screen">
      <h2>Hola, ${esc(u.nombre.split(' ')[0])}</h2>
      <div class="banner ok">Sesión iniciada correctamente.</div>
      <div class="card"><h3>Mi cuenta</h3>
        <div class="kv"><b>Nombre</b><span>${esc(u.nombre)}</span></div>
        <div class="kv"><b>Correo</b><span>${esc(u.email)}</span></div>
        <div class="kv"><b>Matrícula</b><span>${esc(u.matricula)}</span></div></div>
      <div class="card"><h3>Mi privacidad</h3>
        <div class="kv"><b>Aviso aceptado</b><span>versión ${esc(u.consent.version)}</span></div>
        <div class="kv"><b>Fecha de consentimiento</b><span>${esc(new Date(u.consent.fecha).toLocaleString('es-MX'))}</span></div>
        <div class="kv"><b>Finalidades necesarias</b><span>Aceptadas</span></div>
        <div class="kv"><b>Avisos del campus</b><span>${u.consent.marketing ? 'Aceptados' : 'No aceptados'}</span></div></div>
      <div style="flex:1"></div>
      <button class="btn ghost" id="btn-del">Cancelar mi cuenta y borrar mis datos</button>
      <button class="btn" id="btn-out">Cerrar sesión</button></section>`;
  }
};

/* ---------- Render y eventos ---------- */
function go(name, opts) {
  $app.innerHTML = views[name](opts);
  window.scrollTo(0, 0);
  bind(name);
}

function bind(name) {
  $app.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', () => {
    if (b.dataset.go === 'welcome' && name === 'rechazo') draft = { nombre: '', email: '', matricula: '', pass: '', pass2: '' };
    go(b.dataset.go);
  }));

  if (name === 'registro') {
    const f = document.getElementById('f-reg');
    const pass = f.querySelector('#pass'), bar = f.querySelector('#bar');
    const paint = () => { const s = strength(pass.value); bar.style.width = (s * 25) + '%'; bar.style.background = ['#b3261e', '#b3261e', '#d98a00', '#7aa020', '#1e7a46'][s]; };
    pass.addEventListener('input', paint); paint();
    f.addEventListener('submit', async e => {
      e.preventDefault();
      const v = { nombre: f.nombre.value.trim(), email: f.email.value.trim().toLowerCase(), matricula: f.matricula.value.trim(), pass: f.pass.value, pass2: f.pass2.value };
      draft = v;
      const errs = {};
      if (v.nombre.split(/\s+/).filter(Boolean).length < 2 || v.nombre.length < 5) errs.nombre = 'Escribe tu nombre completo.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.email)) errs.email = 'Escribe un correo válido.';
      else if (db.find(v.email)) errs.email = 'Este correo ya está registrado.';
      if (!/^\d{6}$/.test(v.matricula)) errs.matricula = 'La matrícula debe tener 6 dígitos.';
      if (strength(v.pass) < 3 || v.pass.length < 8) errs.pass = 'La contraseña no cumple los requisitos.';
      if (v.pass !== v.pass2) errs.pass2 = 'Las contraseñas no coinciden.';
      ['nombre', 'email', 'matricula', 'pass', 'pass2'].forEach(k => setErr(f, k, errs[k]));
      if (Object.keys(errs).length) return;
      go('aviso');
    });
  }

  if (name === 'aviso') {
    const a = $app.querySelector('#c-aviso'), d = $app.querySelector('#c-datos'), btn = $app.querySelector('#btn-crear');
    const upd = () => { btn.disabled = !(a.checked && d.checked); };
    a.addEventListener('change', upd); d.addEventListener('change', upd);
    btn.addEventListener('click', async () => {
      if (!(a.checked && d.checked)) { $app.querySelector('#aviso-err').hidden = false; return; }
      btn.disabled = true;
      const { salt, hash } = await hashPassword(draft.pass);
      const users = db.users();
      users.push({
        id: crypto.randomUUID(), nombre: draft.nombre, email: draft.email, matricula: draft.matricula, salt, hash,
        consent: { version: AVISO_VERSION, fecha: new Date().toISOString(), necesarias: true, marketing: $app.querySelector('#c-mkt').checked }
      });
      db.save(users);
      const email = draft.email;
      draft = { nombre: '', email: '', matricula: '', pass: '', pass2: '' };
      go('login', { ok: true, email });
    });
  }

  if (name === 'login') {
    const f = document.getElementById('f-login');
    f.addEventListener('submit', async e => {
      e.preventDefault();
      const email = f['l-email'].value.trim().toLowerCase(), pass = f['l-pass'].value;
      const box = document.getElementById('login-err'); box.hidden = true;
      setErr(f, 'email', /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) ? '' : 'Escribe un correo válido.');
      setErr(f, 'pass', pass ? '' : 'Escribe tu contraseña.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) || !pass) return;
      const u = db.find(email);
      const probe = await hashPassword(pass, u ? u.salt : b64(new Uint8Array(16)));
      if (!u || probe.hash !== u.hash) { box.textContent = 'Correo o contraseña incorrectos.'; box.hidden = false; return; }
      db.setSession({ id: u.id, t: Date.now() });
      go('home');
    });
  }

  if (name === 'home') {
    $app.querySelector('#btn-out').addEventListener('click', () => { db.setSession(null); go('welcome'); });
    $app.querySelector('#btn-del').addEventListener('click', () => {
      if (!confirm('Se borrarán tu cuenta y tus datos de este dispositivo. ¿Continuar?')) return;
      const s = db.session(); db.save(db.users().filter(u => u.id !== s.id)); db.setSession(null); go('welcome');
    });
  }
}

go(db.session() ? 'home' : 'welcome');
