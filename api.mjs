// API do site (Netlify Function + Netlify Blobs). Contas, fichas, permissões, grupos e repositório.
import { getStore } from '@netlify/blobs';
import { createHmac, randomBytes, scryptSync, timingSafeEqual, randomUUID } from 'node:crypto';

export const config = { path: '/api/*' };

const SECRET = process.env.SECRET || 'troque-esta-chave-no-netlify';
const store = () => getStore({ name: 'rpg', consistency: 'strong' });
const J = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { 'content-type': 'application/json' } });
const str = (s, n) => String(s || '').trim().slice(0, n);
const key = (pre, s) => pre + '/' + encodeURIComponent(s);
const hash = (s, salt) => scryptSync(String(s), salt, 32).toString('hex');
const sign = n => { const b = Buffer.from(n).toString('base64url'); return b + '.' + createHmac('sha256', SECRET).update(b).digest('base64url'); };
const who = t => {
  const [b] = String(t || '').split('.');
  if (!b) return null;
  const n = Buffer.from(b, 'base64url').toString(), ok = sign(n);
  return ok.length === String(t).length && timingSafeEqual(Buffer.from(ok), Buffer.from(String(t))) ? n : null;
};

export default async req => {
  const s = store(), p = new URL(req.url).pathname.replace(/^\/api/, '');
  const b = req.method === 'POST' ? await req.json().catch(() => ({})) : {};

  if (p === '/login') {
    const n = str(b.nome, 30);
    if (n.length < 2 || String(b.senha || '').length < 4) return J({ erro: 'Nome com 2+ letras e senha com 4+ caracteres.' }, 400);
    let us = await s.get(key('u', n), { type: 'json' });
    if (!us) { const salt = randomBytes(8).toString('hex'); us = { salt, hash: hash(b.senha, salt) }; await s.setJSON(key('u', n), us); }
    else if (!timingSafeEqual(Buffer.from(us.hash), Buffer.from(hash(b.senha, us.salt)))) return J({ erro: 'Senha incorreta.' }, 401);
    return J({ token: sign(n) });
  }

  const u = who(req.headers.get('x-token'));
  if (!u) return J({ erro: 'login' }, 401);
  const lista = async pre => { const { blobs } = await s.list({ prefix: pre }); return (await Promise.all(blobs.map(x => s.get(x.key, { type: 'json' })))).filter(Boolean); };
  // pode editar: dono, usuário liberado (u:nome), grupo liberado (g:grupo) ou todos (*)
  const pode = async f => {
    if (f.dono === u) return true;
    for (const a of f.acesso || []) {
      if (a === '*' || a === 'u:' + u) return true;
      if (a.startsWith('g:')) { const g = await s.get(key('g', a.slice(2)), { type: 'json' }); if (g && g.membros.includes(u)) return true; }
    }
    return false;
  };
  const id = str(b.id, 20).replace(/[^\w-]/g, '');

  if (p === '/estado') {
    const [fichas, repo, gs] = await Promise.all([lista('f/'), lista('r/'), lista('g/')]);
    const grupos = {}; gs.forEach(g => grupos[g.nome] = { dono: g.dono, membros: g.membros });
    return J({ fichas, repo, grupos });
  }
  if (p === '/ficha') {
    if (!id || typeof b.dados !== 'object' || !b.dados) return J({}, 400);
    let f = await s.get(key('f', id), { type: 'json' });
    if (!f) f = { id, dono: u, acesso: [] };
    else if (!(await pode(f))) return J({}, 403);
    f.dados = b.dados;
    if (f.dono === u && Array.isArray(b.acesso)) f.acesso = b.acesso.map(a => str(a, 40));
    await s.setJSON(key('f', id), f); return J({});
  }
  if (p === '/ficha/del') {
    const f = await s.get(key('f', id), { type: 'json' });
    if (!f || f.dono !== u) return J({}, 403);
    await s.delete(key('f', id)); return J({});
  }
  if (p === '/repo') {
    if (!b.tipo || typeof b.dados !== 'object' || !b.dados) return J({}, 400);
    const rid = id || randomUUID().slice(0, 12);
    await s.setJSON(key('r', rid), { id: rid, tipo: str(b.tipo, 20), autor: u, dados: b.dados }); return J({});
  }
  if (p === '/repo/del') {
    const r = await s.get(key('r', id), { type: 'json' });
    if (!r || r.autor !== u) return J({}, 403);
    await s.delete(key('r', id)); return J({});
  }
  if (p === '/grupo') {
    const n = str(b.nome, 30), g = n && await s.get(key('g', n), { type: 'json' });
    if (!n || (g && g.dono !== u)) return J({}, 403);
    const membros = [...new Set((b.membros || []).map(m => str(m, 30)).filter(Boolean))];
    await s.setJSON(key('g', n), { nome: n, dono: u, membros }); return J({});
  }
  return J({}, 404);
};
