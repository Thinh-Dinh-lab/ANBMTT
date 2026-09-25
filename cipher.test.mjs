import assert from 'node:assert/strict';
import {
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
  Z26_ALPHABET,
  Z29_ALPHABET,
} from './cipher.mjs';

assert.equal(caesarEncrypt('HELLO', 3, 'Z26'), 'KHOOR');
assert.equal(caesarDecrypt('KHOOR', 3, 'Z26'), 'HELLO');
assert.equal(substitutionEncrypt('HELLO', 'ZEBRA', 'Z26'), substitutionEncrypt('HELLO', 'ZEBRA', 'Z26'));
assert.equal(vigenereEncrypt('ABC', 'B', 'Z26'), 'BCD');
assert.equal(vigenereDecrypt('BCD', 'B', 'Z26'), 'ABC');
assert.equal(affineEncrypt('A', 1, 2, 'Z26'), 'C');
assert.equal(affineDecrypt('C', 1, 2, 'Z26'), 'A');
const hillText = 'HELLO';
const hillKey = [ [6, 24], [1, 13] ];
const encrypted = hillEncrypt(hillText, hillKey, 'Z26');
assert.equal(hillDecrypt(encrypted, hillKey, 'Z26'), 'HELLO');
assert.equal(normalizeText('ăn ghê', 'Z29'), 'ĂN GHÊ');
assert.equal(Z26_ALPHABET.length, 26);
assert.equal(Z29_ALPHABET.length, 29);
console.log('All cipher tests passed.');
