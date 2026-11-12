// Acceso único DATA Miazzo: la puerta central, en datamiazzo.com.ar.
//   /acceso/           página para entrar (estática, en acceso/index.html)
//   /acceso/ir         reconoce a la persona y la manda al sitio con un ticket
//   /acceso/salir      cierra la sesión central
//   /api/acceso/*      lo que usa la página: pedir código, verificarlo, Google
// Los permisos salen de la planilla "Base de clientes · DATA Miazzo" a través
// de un Apps Script (DM_APPS_SCRIPT_URL + DM_APPS_SCRIPT_CLAVE), que también
// manda los mails con el código desde datamiazzo@gmail.com.
import {
  CENTRAL, SITIOS, DIAS_ID, ahora, env, firmar, leerPase, leerCookie, cookie,
  redirigir, json, volverSeguro, normalizarMail, mailValido,
} from '../acceso-lib.js';

const ID = 'dm_id';

async function script(accion, params = {}) {
  const base = env('DM_APPS_SCRIPT_URL');
  if (!base) return { ok: false, error: 'servicio' };
  const u = new URL(base);
  u.searchParams.set('accion', accion);
  u.searchParams.set('clave', env('DM_APPS_SCRIPT_CLAVE'));
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  try {
    const r = await fetch(u.toString(), { redirect: 'follow', signal: AbortSignal.timeout(15000) });
    const d = JSON.parse(await r.text());
    return d && typeof d === 'object' ? d : { ok: false, error: 'servicio' };
  } catch {
    return { ok: false, error: 'servicio' };
  }
}

function algunPermiso(p) {
  return !!p && Object.keys(SITIOS).some((k) => p[k]);
}

async function paseId(email, nombre, permisos, vence) {
  const x = vence || ahora() + DIAS_ID * 86400;
  const pase = await firmar({ t: 'id', e: email, n: nombre || '', p: permisos || {}, x });
  return cookie(ID, pase, Math.max(0, x - ahora()));
}

async function leerCuerpo(req) {
  try { return await req.json(); } catch { return {}; }
}

export default async (req, context) => {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, '') || '/';

  // ---------- /acceso/ir ----------
  if (p === '/acceso/ir') {
    const sitio = url.searchParams.get('sitio');
    if (!SITIOS[sitio]) return redirigir(url.origin + '/acceso/');
    const volver = volverSeguro(url.searchParams.get('volver'), SITIOS[sitio].dash);
    const qs = `sitio=${sitio}&volver=${encodeURIComponent(volver)}`;
    const id = await leerPase(leerCookie(req, ID), 'id');
    if (!id) return redirigir(`${url.origin}/acceso/?${qs}`);

    // Permisos frescos de la planilla; si el Apps Script no responde, se usan
    // los que quedaron guardados en el pase al último control.
    const r = await script('permisos', { email: id.e });
    let permisos = id.p || {};
    const cookies = [];
    if (r.ok) {
      if (!r.encontrado || !algunPermiso(r.permisos)) {
        return redirigir(`${url.origin}/acceso/?${qs}&error=sin_acceso`, [cookie(ID, '', 0)]);
      }
      permisos = r.permisos;
      cookies.push(await paseId(id.e, r.nombre, permisos, id.x));
    }
    if (!permisos[sitio]) return redirigir(`${url.origin}/acceso/sin-permiso/?sitio=${sitio}`, cookies);
    const ticket = await firmar({ t: 'ticket', s: sitio, e: id.e, x: ahora() + 120 });
    return redirigir(`${SITIOS[sitio].url}/acceso/entrar?t=${encodeURIComponent(ticket)}&volver=${encodeURIComponent(volver)}`, cookies);
  }

  // ---------- /acceso/salir ----------
  // Cierra la sesión central y pasa por los tres sitios para cerrar la de cada uno.
  if (p === '/acceso/salir') {
    const [primero, ...resto] = Object.keys(SITIOS);
    return redirigir(`${SITIOS[primero].url}/acceso/salir?cadena=${resto.join(',')}`, [cookie(ID, '', 0)]);
  }

  // ---------- API ----------
  if (p === '/api/acceso/config') {
    return json({ google: env('DM_GOOGLE_CLIENT_ID') || null });
  }

  if (p === '/api/acceso/yo') {
    const id = await leerPase(leerCookie(req, ID), 'id');
    if (!id) return json({ ok: false });
    const r = await script('permisos', { email: id.e });
    if (r.ok && (!r.encontrado || !algunPermiso(r.permisos))) return json({ ok: false, error: 'sin_acceso' }, 200, [cookie(ID, '', 0)]);
    const permisos = r.ok ? r.permisos : id.p || {};
    return json({ ok: true, email: id.e, nombre: (r.ok ? r.nombre : id.n) || '', permisos });
  }

  if (req.method !== 'POST') return json({ ok: false, error: 'metodo' }, 405);
  const cuerpo = await leerCuerpo(req);

  if (p === '/api/acceso/codigo') {
    const email = normalizarMail(cuerpo.email);
    if (!mailValido(email)) return json({ ok: false, error: 'mail' });
    const r = await script('enviar', { email });
    return json({ ok: !!r.ok, error: r.ok ? undefined : r.error || 'servicio' });
  }

  if (p === '/api/acceso/verificar') {
    const email = normalizarMail(cuerpo.email);
    const codigo = String(cuerpo.codigo || '').replace(/\D/g, '');
    if (!mailValido(email) || codigo.length !== 6) return json({ ok: false, error: 'incorrecto' });
    const r = await script('verificar', { email, codigo });
    if (!r.ok) return json({ ok: false, error: r.error || 'servicio' });
    return json({ ok: true, nombre: r.nombre || '', permisos: r.permisos }, 200, [await paseId(email, r.nombre, r.permisos)]);
  }

  if (p === '/api/acceso/google') {
    const clienteId = env('DM_GOOGLE_CLIENT_ID');
    if (!clienteId || !cuerpo.credential) return json({ ok: false, error: 'google' });
    let t;
    try {
      const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cuerpo.credential), { signal: AbortSignal.timeout(10000) });
      t = await r.json();
    } catch {
      return json({ ok: false, error: 'google' });
    }
    const valido = t && t.aud === clienteId && String(t.email_verified) === 'true' &&
      ['accounts.google.com', 'https://accounts.google.com'].includes(t.iss) && Number(t.exp) > ahora();
    if (!valido) return json({ ok: false, error: 'google' });
    const email = normalizarMail(t.email);
    const r = await script('permisos', { email, registrar: 'Google' });
    if (!r.ok) return json({ ok: false, error: r.error || 'servicio' });
    if (!r.encontrado || !algunPermiso(r.permisos)) return json({ ok: false, error: 'sin_acceso', email });
    return json({ ok: true, nombre: r.nombre || '', permisos: r.permisos }, 200, [await paseId(email, r.nombre, r.permisos)]);
  }

  return json({ ok: false, error: 'ruta' }, 404);
};

export const config = { path: ['/acceso/ir', '/acceso/salir', '/api/acceso/*'] };
