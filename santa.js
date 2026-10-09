// Общая криптография для жеребьёвки Тайного Санты.
// Идея: каждому участнику выдаётся секретный код. По коду вычисляется
// идентификатор записи и ключ шифрования. В draw.json лежат только
// зашифрованные записи — без кода прочитать, кто кому дарит, нельзя.

const SANTA = (() => {
  // Алфавит без похожих символов (0/O, 1/I/L), чтобы код было легко продиктовать
  const ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
  const CODE_LEN = 10;          // ~49 бит энтропии
  const ITERATIONS = 150000;    // PBKDF2: перебор кодов становится очень медленным
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  const fromHex = (hex) => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  // Приводим ввод к каноничному виду: верхний регистр, без пробелов и дефисов,
  // кириллица-двойник (А, В, Е, К...) превращается в латиницу
  const LOOKALIKE = { "А":"A","В":"B","Е":"E","К":"K","М":"M","Н":"H","Р":"P","С":"C","Т":"T","Х":"X","У":"Y" };
  function normalize(code) {
    return code.toUpperCase()
      .replace(/[АВЕКМНРСТХУ]/g, ch => LOOKALIKE[ch])
      .replace(/[\s\-_]/g, "");
  }

  function pretty(code) {
    return code.slice(0, 5) + "-" + code.slice(5);
  }

  function randomCode() {
    const out = [];
    const limit = 256 - (256 % ALPHABET.length); // без перекоса распределения
    while (out.length < CODE_LEN) {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      for (const b of bytes) {
        if (b < limit && out.length < CODE_LEN) out.push(ALPHABET[b % ALPHABET.length]);
      }
    }
    return out.join("");
  }

  function randomIndex(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    let x;
    do { x = crypto.getRandomValues(new Uint32Array(1))[0]; } while (x >= limit);
    return x % n;
  }

  // Перемешивание Фишера–Йетса на криптостойком генераторе
  function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = randomIndex(i + 1);
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  // Правило 4 из README: вытянул себя — перемешиваем заново
  function draw(names) {
    if (names.length < 2) throw new Error("Нужно хотя бы 2 участника");
    let receivers;
    do { receivers = shuffle(names); } while (receivers.some((r, i) => r === names[i]));
    return names.map((giver, i) => ({ giver, receiver: receivers[i] }));
  }

  async function entryId(code) {
    const h = await crypto.subtle.digest("SHA-256", enc.encode("santa-id:" + code));
    return toHex(h).slice(0, 24);
  }

  async function deriveKey(code, id) {
    const base = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: fromHex(id), iterations: ITERATIONS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function sealEntry(code, payload) {
    const id = await entryId(code);
    const key = await deriveKey(code, id);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(payload)));
    return { id, iv: toB64(iv), ct: toB64(ct) };
  }

  async function openEntry(rawCode, data) {
    const code = normalize(rawCode);
    if (code.length !== CODE_LEN) return null;
    const id = await entryId(code);
    const entry = data.entries.find(e => e.id === id);
    if (!entry) return null;
    const key = await deriveKey(code, id);
    try {
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(entry.iv) }, key, fromB64(entry.ct));
      return JSON.parse(dec.decode(pt));
    } catch { return null; }
  }

  // Полный цикл для организатора: жеребьёвка + коды + зашифрованный файл.
  // Пары наружу не отдаются — только «имя → код».
  async function buildDraw(names, eventName) {
    const pairs = draw(names);
    const codes = [];
    const entries = [];
    const used = new Set();
    for (const p of pairs) {
      let code;
      do { code = randomCode(); } while (used.has(code));
      used.add(code);
      entries.push(await sealEntry(code, p));
      codes.push({ name: p.giver, code: pretty(code) });
    }
    return {
      codes,
      file: {
        event: eventName,
        created: new Date().toISOString().slice(0, 10),
        participants: names.length,
        entries: shuffle(entries), // порядок записей не выдаёт порядок участников
      },
    };
  }

  return { normalize, pretty, draw, buildDraw, openEntry, CODE_LEN };
})();

if (typeof module !== "undefined") module.exports = SANTA;
