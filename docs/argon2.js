// Arrabona Pass Mobil - Argon2id (RFC 9106, v1.3) + BLAKE2b, tiszta JavaScript.
// A Pass asztali trezoraval bitre azonos kulcsot ad (ellenorizve a Python 'cryptography' konyvtarral).
// 64 bites szamok: (lo, hi) 32 bites parok Uint32Array-ben.
"use strict";

const Argon2 = (() => {
  // ---------------------------------------------------------------- BLAKE2b
  const IV = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19]);
  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];
  const v = new Uint32Array(32), mw = new Uint32Array(32);

  function add64(a, b) {           // v[a] += v[b]
    const lo = v[a] + v[b];
    v[a + 1] = v[a + 1] + v[b + 1] + (lo / 0x100000000 >= 1 ? 1 : 0);
    v[a] = lo;
  }
  function addM(a, i) {            // v[a] += m[i]
    const lo = v[a] + mw[i];
    v[a + 1] = v[a + 1] + mw[i + 1] + (lo / 0x100000000 >= 1 ? 1 : 0);
    v[a] = lo;
  }
  function xorRot(a, b, n) {       // v[a] = rotr64(v[a] ^ v[b], n)
    const xl = v[a] ^ v[b], xh = v[a + 1] ^ v[b + 1];
    if (n === 32) { v[a] = xh; v[a + 1] = xl; }
    else if (n < 32) { v[a] = (xl >>> n) | (xh << (32 - n)); v[a + 1] = (xh >>> n) | (xl << (32 - n)); }
    else { n -= 32; v[a] = (xh >>> n) | (xl << (32 - n)); v[a + 1] = (xl >>> n) | (xh << (32 - n)); }
  }
  function G(a, b, c, d, x, y) {
    add64(a, b); addM(a, x); xorRot(d, a, 32);
    add64(c, d); xorRot(b, c, 24);
    add64(a, b); addM(a, y); xorRot(d, a, 16);
    add64(c, d); xorRot(b, c, 63);
  }
  function compress(h, block, t, last) {
    for (let i = 0; i < 16; i++) { v[i] = h[i]; v[i + 16] = IV[i]; }
    v[24] ^= t; v[25] ^= (t / 0x100000000) >>> 0;
    if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
    for (let i = 0; i < 32; i++)
      mw[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      G(0, 8, 16, 24, s[0] * 2, s[1] * 2); G(2, 10, 18, 26, s[2] * 2, s[3] * 2);
      G(4, 12, 20, 28, s[4] * 2, s[5] * 2); G(6, 14, 22, 30, s[6] * 2, s[7] * 2);
      G(0, 10, 20, 30, s[8] * 2, s[9] * 2); G(2, 12, 22, 24, s[10] * 2, s[11] * 2);
      G(4, 14, 16, 26, s[12] * 2, s[13] * 2); G(6, 8, 18, 28, s[14] * 2, s[15] * 2);
    }
    for (let i = 0; i < 16; i++) h[i] ^= v[i] ^ v[i + 16];
  }
  function blake2b(outLen, ...parts) {
    const h = new Uint32Array(IV);
    h[0] ^= 0x01010000 ^ outLen;
    const buf = new Uint8Array(128);
    let fill = 0, t = 0;
    for (const p of parts) {
      for (let i = 0; i < p.length; i++) {
        if (fill === 128) { t += 128; compress(h, buf, t, false); fill = 0; }
        buf[fill++] = p[i];
      }
    }
    t += fill;
    buf.fill(0, fill);
    compress(h, buf, t, true);
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = h[i >> 2] >>> (8 * (i & 3));
    return out;
  }
  function le32(n) { return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]); }

  // H' (valtozo hosszu hash)
  function hPrime(T, ...parts) {
    if (T <= 64) return blake2b(T, le32(T), ...parts);
    const out = new Uint8Array(T);
    const r = Math.ceil(T / 32) - 2;
    let V = blake2b(64, le32(T), ...parts);
    out.set(V.subarray(0, 32), 0);
    for (let i = 1; i < r; i++) { V = blake2b(64, V); out.set(V.subarray(0, 32), i * 32); }
    V = blake2b(T - 32 * r, V);
    out.set(V, 32 * r);
    return out;
  }

  // ---------------------------------------------------------------- Argon2 G (blokk-tomorites)
  // 64x64 -> 64 bites szorzas also 32 bitje es felso 32 bitje (16 bites reszekkel, pontosan)
  const R = new Uint32Array(256), Q = new Uint32Array(256);  // R = X^Y ; Q munkamasolat

  // GB egy lepesben, a 64x64 szorzas also 32 bitje pontosan (Math.imul), a felso a kozelitesbol
  // (a lebegopontos hiba < 2^12, ezert a kerekites pontos)
  const T32 = 4294967296;
  function GB(w, a, b, c, d) {
    let al = w[a], ah = w[a + 1], bl = w[b], bh = w[b + 1], cl = w[c], ch = w[c + 1], dl = w[d], dh = w[d + 1];
    let ml, mh, lo, xl, xh;
    // a = a + b + 2*al*bl
    ml = Math.imul(al, bl) >>> 0; mh = Math.round((al * bl - ml) / T32);
    lo = al + bl; ah = (ah + bh + (lo >= T32 ? 1 : 0)) >>> 0; lo >>>= 0;
    ml = ml * 2; mh = mh * 2 + (ml >= T32 ? 1 : 0); ml >>>= 0;
    al = lo + ml; ah = (ah + mh + (al >= T32 ? 1 : 0)) >>> 0; al >>>= 0;
    xl = (dl ^ al) >>> 0; xh = (dh ^ ah) >>> 0; dl = xh; dh = xl;                   // rotr 32
    ml = Math.imul(cl, dl) >>> 0; mh = Math.round((cl * dl - ml) / T32);
    lo = cl + dl; ch = (ch + dh + (lo >= T32 ? 1 : 0)) >>> 0; lo >>>= 0;
    ml = ml * 2; mh = mh * 2 + (ml >= T32 ? 1 : 0); ml >>>= 0;
    cl = lo + ml; ch = (ch + mh + (cl >= T32 ? 1 : 0)) >>> 0; cl >>>= 0;
    xl = bl ^ cl; xh = bh ^ ch; bl = ((xl >>> 24) | (xh << 8)) >>> 0; bh = ((xh >>> 24) | (xl << 8)) >>> 0;   // rotr 24
    ml = Math.imul(al, bl) >>> 0; mh = Math.round((al * bl - ml) / T32);
    lo = al + bl; ah = (ah + bh + (lo >= T32 ? 1 : 0)) >>> 0; lo >>>= 0;
    ml = ml * 2; mh = mh * 2 + (ml >= T32 ? 1 : 0); ml >>>= 0;
    al = lo + ml; ah = (ah + mh + (al >= T32 ? 1 : 0)) >>> 0; al >>>= 0;
    xl = dl ^ al; xh = dh ^ ah; dl = ((xl >>> 16) | (xh << 16)) >>> 0; dh = ((xh >>> 16) | (xl << 16)) >>> 0;  // rotr 16
    ml = Math.imul(cl, dl) >>> 0; mh = Math.round((cl * dl - ml) / T32);
    lo = cl + dl; ch = (ch + dh + (lo >= T32 ? 1 : 0)) >>> 0; lo >>>= 0;
    ml = ml * 2; mh = mh * 2 + (ml >= T32 ? 1 : 0); ml >>>= 0;
    cl = lo + ml; ch = (ch + mh + (cl >= T32 ? 1 : 0)) >>> 0; cl >>>= 0;
    xl = bl ^ cl; xh = bh ^ ch; bl = (xh >>> 31) | (xl << 1); bh = (xl >>> 31) | (xh << 1);  // rotr 63
    w[a] = al; w[a + 1] = ah; w[b] = bl; w[b + 1] = bh; w[c] = cl; w[c + 1] = ch; w[d] = dl; w[d + 1] = dh;
  }
  function P(w, i) {
    GB(w, i[0], i[4], i[8], i[12]); GB(w, i[1], i[5], i[9], i[13]);
    GB(w, i[2], i[6], i[10], i[14]); GB(w, i[3], i[7], i[11], i[15]);
    GB(w, i[0], i[5], i[10], i[15]); GB(w, i[1], i[6], i[11], i[12]);
    GB(w, i[2], i[7], i[8], i[13]); GB(w, i[3], i[4], i[9], i[14]);
  }
  const ROWS = [], COLS = [];
  for (let r = 0; r < 8; r++) {
    const a = []; for (let k = 0; k < 16; k++) a.push((16 * r + k) * 2); ROWS.push(a);
  }
  for (let c = 0; c < 8; c++) {
    const a = [];
    for (let k = 0; k < 8; k++) { a.push((2 * c + 16 * k) * 2); a.push((2 * c + 16 * k + 1) * 2); }
    COLS.push(a);
  }
  // out = G(X, Y) [xor out, ha withXor]; mem-ben eltolasok (uint32 egysegben)
  function fill(mem, outOff, xOff, yOff, withXor) {
    for (let i = 0; i < 256; i++) R[i] = mem[xOff + i] ^ mem[yOff + i];
    Q.set(R);
    for (let r = 0; r < 8; r++) P(Q, ROWS[r]);
    for (let c = 0; c < 8; c++) P(Q, COLS[c]);
    if (withXor) for (let i = 0; i < 256; i++) mem[outOff + i] ^= Q[i] ^ R[i];
    else for (let i = 0; i < 256; i++) mem[outOff + i] = Q[i] ^ R[i];
  }
  // cimblokk: addr = G(0, G(0, input))
  function addressBlock(input, out) {
    const tmp = new Uint32Array(256 * 3);
    tmp.set(input, 256);                 // [0..255] nulla, [256..511] input
    fill(tmp, 512, 0, 256, false);       // tmp2 = G(0, input)
    tmp.set(tmp.subarray(512, 768), 256);
    fill(tmp, 512, 0, 256, false);       // G(0, tmp2)
    out.set(tmp.subarray(512, 768));
  }
  function mulhi(a, b) {               // (a*b) >> 32, a,b < 2^32
    const al = a & 0xffff, ah = a >>> 16, bl = b & 0xffff, bh = b >>> 16;
    const ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    const mid = (ll >>> 16) + (lh & 0xffff) + (hl & 0xffff);
    return (hh + (lh >>> 16) + (hl >>> 16) + (mid >>> 16)) >>> 0;
  }

  // ---------------------------------------------------------------- Argon2id
  // password, salt: Uint8Array ; m: KiB ; onProgress(0..1) opcionalis
  async function argon2id({ password, salt, t, m, p, hashLen = 32, onProgress }) {
    const y = 2, ver = 0x13;
    const H0 = blake2b(64, le32(p), le32(hashLen), le32(m), le32(t), le32(ver), le32(y),
      le32(password.length), password, le32(salt.length), salt, le32(0), le32(0));
    const mBlocks = 4 * p * Math.floor(m / (4 * p));
    const q = mBlocks / p, segLen = q / 4;
    const mem = new Uint32Array(mBlocks * 256);
    const off = (lane, col) => (lane * q + col) * 256;
    const toWords = (bytes, dst) => {
      for (let i = 0; i < 256; i++)
        dst[i] = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24);
    };
    for (let l = 0; l < p; l++) {
      toWords(hPrime(1024, H0, le32(0), le32(l)), mem.subarray(off(l, 0), off(l, 0) + 256));
      toWords(hPrime(1024, H0, le32(1), le32(l)), mem.subarray(off(l, 1), off(l, 1) + 256));
    }
    const input = new Uint32Array(256), addr = new Uint32Array(256);
    const total = t * 4 * p;
    let done = 0, lastYield = Date.now();
    for (let pass = 0; pass < t; pass++) {
      for (let sl = 0; sl < 4; sl++) {
        for (let l = 0; l < p; l++) {
          const indep = pass === 0 && sl < 2;
          if (indep) {
            input.fill(0);
            input[0] = pass; input[2] = l; input[4] = sl; input[6] = mBlocks; input[8] = t; input[10] = y;
            input[12] = 0;
          }
          const start = pass === 0 && sl === 0 ? 2 : 0;
          if (indep && start !== 0) { input[12]++; addressBlock(input, addr); }
          for (let i = start; i < segLen; i++) {
            const col = sl * segLen + i;
            const prevCol = col === 0 ? q - 1 : col - 1;
            let J1, J2;
            if (indep) {
              if (i % 128 === 0) { input[12]++; addressBlock(input, addr); }
              J1 = addr[(i % 128) * 2]; J2 = addr[(i % 128) * 2 + 1];
            } else {
              const po = off(l, prevCol);
              J1 = mem[po]; J2 = mem[po + 1];
            }
            const refLane = pass === 0 && sl === 0 ? l : J2 % p;
            const same = refLane === l;
            let W;
            if (pass === 0) W = same ? sl * segLen + i - 1 : sl * segLen + (i === 0 ? -1 : 0);
            else W = same ? q - segLen + i - 1 : q - segLen + (i === 0 ? -1 : 0);
            const x = mulhi(J1, J1);
            const yy = mulhi(W, x);
            const rel = W - 1 - yy;
            const startPos = pass === 0 ? 0 : (sl === 3 ? 0 : (sl + 1) * segLen);
            const refCol = (startPos + rel) % q;
            fill(mem, off(l, col), off(l, prevCol), off(refLane, refCol), pass > 0);
          }
          done++;
          if (Date.now() - lastYield > 40) {     // a felulet ne fagyjon le
            if (onProgress) onProgress(done / total);
            await new Promise(r => setTimeout(r, 0));
            lastYield = Date.now();
          }
        }
      }
    }
    const C = new Uint32Array(256);
    for (let l = 0; l < p; l++) { const o = off(l, q - 1); for (let i = 0; i < 256; i++) C[i] ^= mem[o + i]; }
    mem.fill(0);
    const Cb = new Uint8Array(1024);
    for (let i = 0; i < 256; i++) { Cb[i * 4] = C[i]; Cb[i * 4 + 1] = C[i] >>> 8; Cb[i * 4 + 2] = C[i] >>> 16; Cb[i * 4 + 3] = C[i] >>> 24; }
    if (onProgress) onProgress(1);
    return hPrime(hashLen, Cb);
  }
  return { argon2id, blake2b };
})();
if (typeof module !== "undefined") module.exports = Argon2;
