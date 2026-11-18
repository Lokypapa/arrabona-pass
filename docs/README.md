# Arrabona Pass Mobil

Az [Arrabona Pass](../README.md) jelszókezelő csak olvasható telefonos nézője (PWA), GitHub Pages-ről:
https://lokypapa.github.io/arrabona-pass/

- A trezor (`ArrabonaPass_mobil.apv`) titkosítva marad a telefonon is; a feloldás helyben történik
  (Argon2id + AES-256-GCM), internet nélkül. Az app semmilyen adatot nem küld sehova
  (a Content-Security-Policy is tiltja).
- Face ID: WebAuthn passkey + PRF (iOS 18+). A trezor kulcsát egy csak Face ID-val elérhető titokkal csomagolja be.
- Fájlok: `index.html`, `app.js`, `argon2.js` (Argon2id + BLAKE2b tiszta JS-ben), `app.css`, `sw.js` (offline), `manifest.webmanifest`.
