export const Z26_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const Z29_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function makeAlphabetForMode(mode) {
  return mode === 'Z29' ? Z29_ALPHABET : Z26_ALPHABET;
}

function charIndex(char, alphabet) {
  const upper = char.toUpperCase();
  const idx = alphabet.indexOf(upper);
  if (idx === -1) return null;
  return idx;
}

function normalizeText(text, mode) {
  const alphabet = makeAlphabetForMode(mode);
  const normalized = [];
  const map = {};
  for (const ch of text.toUpperCase()) {
    if (alphabet.includes(ch)) {
      normalized.push(ch);
      map[ch] = true;
    }
  }
  return normalized.join('');
}

function shiftChar(ch, shift, alphabet) {
  const idx = charIndex(ch, alphabet);
  if (idx === null) return ch;
  return alphabet[(idx + shift + alphabet.length) % alphabet.length];
}

export function caesarEncrypt(plainText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  return plainText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      return idx === null ? ch : alphabet[(idx + Number(key)) % alphabet.length];
    })
    .join('');
}

export function caesarDecrypt(cipherText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  return cipherText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      return idx === null ? ch : alphabet[(idx - Number(key) + alphabet.length) % alphabet.length];
    })
    .join('');
}

export function substitutionEncrypt(plainText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const mapping = new Map();
  const cleanedKey = key.toUpperCase().replace(/[^A-Z0-9]/g, '');

  for (let i = 0; i < cleanedKey.length; i += 1) {
    if (!alphabet.includes(cleanedKey[i])) continue;
    if (!mapping.has(cleanedKey[i])) {
      mapping.set(cleanedKey[i], alphabet[i % alphabet.length]);
    }
  }

  return plainText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      return mapping.has(ch) ? mapping.get(ch) : alphabet[(idx + 1) % alphabet.length];
    })
    .join('');
}

export function substitutionDecrypt(cipherText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const mapping = new Map();
  const cleanedKey = key.toUpperCase().replace(/[^A-Z0-9]/g, '');

  for (let i = 0; i < cleanedKey.length; i += 1) {
    if (!alphabet.includes(cleanedKey[i])) continue;
    if (!mapping.has(cleanedKey[i])) {
      mapping.set(cleanedKey[i], alphabet[i % alphabet.length]);
    }
  }

  return cipherText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      return Array.from(mapping.entries()).find(([_, val]) => val === ch)?.[0] ?? ch;
    })
    .join('');
}

export function vigenereEncrypt(plainText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const keyChars = key.toUpperCase().replace(/[^A-Z0-9]/g, '').split('');
  let keyIndex = 0;

  return plainText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      const shift = charIndex(keyChars[keyIndex % keyChars.length] || 'A', alphabet);
      keyIndex += 1;
      return alphabet[(idx + shift) % alphabet.length];
    })
    .join('');
}

export function vigenereDecrypt(cipherText, key, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const keyChars = key.toUpperCase().replace(/[^A-Z0-9]/g, '').split('');
  let keyIndex = 0;

  return cipherText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      const shift = charIndex(keyChars[keyIndex % keyChars.length] || 'A', alphabet);
      keyIndex += 1;
      return alphabet[(idx - shift + alphabet.length) % alphabet.length];
    })
    .join('');
}

export function affineEncrypt(plainText, a, b, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const A = Number(a);
  const B = Number(b);

  return plainText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      return alphabet[(A * idx + B) % alphabet.length];
    })
    .join('');
}

export function affineDecrypt(cipherText, a, b, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const A = Number(a);
  const B = Number(b);
  const modularInverse = (() => {
    for (let i = 0; i < alphabet.length; i += 1) {
      if ((A * i) % alphabet.length === 1) return i;
    }
    return null;
  })();

  if (modularInverse === null) throw new Error('A không có nghịch đảo modulo trong alphabet này.');

  return cipherText
    .toUpperCase()
    .split('')
    .map(ch => {
      const idx = charIndex(ch, alphabet);
      if (idx === null) return ch;
      return alphabet[(modularInverse * (idx - B + alphabet.length)) % alphabet.length];
    })
    .join('');
}

function modInverse(num, mod) {
  for (let i = 0; i < mod; i += 1) {
    if ((num * i) % mod === 1) return i;
  }
  return null;
}

function matrixMultiplyVector(matrix, vector, alphabet) {
  return matrix.map((row) => {
    let sum = 0;
    for (let i = 0; i < row.length; i += 1) {
      sum += row[i] * vector[i];
    }
    return sum % alphabet.length;
  });
}

function matrixInverse(matrix, alphabetLength) {
  const determinant = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  const detMod = ((determinant % alphabetLength) + alphabetLength) % alphabetLength;
  const invDet = modInverse(detMod, alphabetLength);
  if (invDet === null) return null;

  return [
    [((matrix[1][1] * invDet) % alphabetLength + alphabetLength) % alphabetLength,
      ((-matrix[0][1] * invDet) % alphabetLength + alphabetLength) % alphabetLength],
    [((-matrix[1][0]) * invDet) % alphabetLength + alphabetLength, ((matrix[0][0] * invDet) % alphabetLength + alphabetLength) % alphabetLength],
  ];
}

export function hillEncrypt(plainText, keyMatrix, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const key = keyMatrix.map(row => row.map(Number));
  const text = normalizeText(plainText, mode);
  if (text.length % 2 !== 0) text += 'X';
  const out = [];

  for (let i = 0; i < text.length; i += 2) {
    const vector = [charIndex(text[i], alphabet), charIndex(text[i + 1], alphabet)];
    const cipherVector = matrixMultiplyVector(key, vector, alphabet);
    out.push(alphabet[cipherVector[0]], alphabet[cipherVector[1]]);
  }

  return out.join('');
}

export function hillDecrypt(cipherText, keyMatrix, mode = 'Z26') {
  const alphabet = makeAlphabetForMode(mode);
  const key = keyMatrix.map(row => row.map(Number));
  const inverse = matrixInverse(key, alphabet.length);

  if (!inverse) throw new Error('Ma trận khóa không khả nghịch theo modulo ' + alphabet.length + '.');

  const text = cipherText.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const out = [];

  for (let i = 0; i < text.length; i += 2) {
    const vector = [charIndex(text[i], alphabet), charIndex(text[i + 1], alphabet)];
    const decrypted = matrixMultiplyVector(inverse, vector, alphabet);
    out.push(alphabet[decrypted[0]], alphabet[decrypted[1]]);
  }

  return out.join('');
}

export default {
  Z26_ALPHABET,
  Z29_ALPHABET,
  caesarEncrypt,
  caesarDecrypt,
  substitutionEncrypt,
  substitutionDecrypt,
  vigenereEncrypt,
  vigenereDecrypt,
  affineEncrypt,
  affineDecrypt,
  hillEncrypt,
  hillDecrypt,
  normalizeText,
};
