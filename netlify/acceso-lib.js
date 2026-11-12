// Acceso único DATA Miazzo: utilidades compartidas por las edge functions.
// Esta misma copia vive en los cuatro sitios (datamiazzo.com.ar y los tres
// Estrategias). Si se cambia acá, hay que copiarla igual en los otros.
//
// Un "pase" es un texto firmado con HMAC-SHA256: base64url(JSON) + "." + firma.
// Tipos de pase:
//   id     → cookie dm_id en datamiazzo.com.ar: quién es la persona (60 días)
//   ticket → viaja en la URL de datamiazzo.com.ar a un sitio Estrategias (2 min)
//   ses    → cookie dm_ses en cada sitio Estrategias (12 horas)
// La clave (DM_ACCESO_SECRETO) es la misma en los cuatro sitios de Netlify.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const CENTRAL = 'https://datamiazzo.com.ar';

export const SITIOS = {
  grano: { nombre: 'Estrategias al Grano', url: 'https://estrategiasalgrano.com', dash: '/' },
  financieras: { nombre: 'Estrategias Financieras', url: 'https://estrategiasfinancieras.com.ar', dash: '/dashboard/' },
  ganaderas: { nombre: 'Estrategias Ganaderas', url: 'https://estrategiasganaderas.com.ar', dash: '/dashboard/' },
};

export const DIAS_ID = 60;   // sesión central (quién sos)
export const HORAS_SES = 12; // sesión en cada sitio; al vencer se revalida en silencio

function b64u(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function desdeB64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export function env(nombre) {
  try { return globalThis.Netlify?.env?.get(nombre) || ''; } catch { return ''; }
}

let _clave = null, _claveTexto = '';
async function clave() {
  const s = env('DM_ACCESO_SECRETO');
  if (!s || s.length < 32) throw new Error('Falta DM_ACCESO_SECRETO');
  if (!_clave || _claveTexto !== s) {
    _clave = await crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    _claveTexto = s;
  }
  return _clave;
}

export const ahora = () => Math.floor(Date.now() / 1000);

export async function firmar(datos) {
  const p = b64u(enc.encode(JSON.stringify(datos)));
  const firma = await crypto.subtle.sign('HMAC', await clave(), enc.encode(p));
  return p + '.' + b64u(firma);
}

export async function leerPase(pase, tipo) {
  if (!pase || typeof pase !== 'string' || pase.length > 4000) return null;
  const partes = pase.split('.');
  if (partes.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await clave(), desdeB64u(partes[1]), enc.encode(partes[0]));
    if (!ok) return null;
    const d = JSON.parse(dec.decode(desdeB64u(partes[0])));
    if (d.t !== tipo || !d.x || d.x < ahora()) return null;
    return d;
  } catch {
    return null;
  }
}

export function leerCookie(req, nombre) {
  const c = req.headers.get('cookie') || '';
  for (const parte of c.split(/;\s*/)) {
    const i = parte.indexOf('=');
    if (i > 0 && parte.slice(0, i) === nombre) {
      try { return decodeURIComponent(parte.slice(i + 1)); } catch { return null; }
    }
  }
  return null;
}

export function cookie(nombre, valor, segundos, { httpOnly = true } = {}) {
  return `${nombre}=${encodeURIComponent(valor)}; Path=/; Max-Age=${segundos}; Secure; SameSite=Lax${httpOnly ? '; HttpOnly' : ''}`;
}

export function redirigir(url, cookies = []) {
  const h = new Headers({ location: url, 'cache-control': 'no-store' });
  for (const c of cookies) h.append('set-cookie', c);
  return new Response(null, { status: 302, headers: h });
}

export function json(datos, status = 200, cookies = []) {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  for (const c of cookies) h.append('set-cookie', c);
  return new Response(JSON.stringify(datos), { status, headers: h });
}

// Solo rutas internas del mismo sitio: evita usar el acceso como redirección abierta.
export function volverSeguro(v, defecto) {
  return typeof v === 'string' && /^\/(?![\/\\])/.test(v) && v.length < 500 ? v : defecto;
}

export function normalizarMail(m) {
  return String(m || '').trim().toLowerCase();
}
export function mailValido(m) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m) && m.length <= 200;
}
