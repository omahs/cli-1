import { fromHex } from '@cosmjs/encoding';
import fs from 'node:fs/promises';
import * as openpgp from 'openpgp';
import * as bcrypt from 'bcrypt';
import nacl from 'tweetnacl';

// Base 64 implementation with custom alphabet to match bcrypt received encoding
const b64ch = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=';
const b64chs = Array.prototype.slice.call(b64ch);
const b64tab = (a => {
  let tab = {};
  for (const [i, c] of a.entries()) tab[c] = i;
  return tab;
})(b64chs);
const btoaPolyfill = bin => {
  // console.log('polyfilled');
  let u32;
  let c0;
  let c1;
  let c2;
  let asc = '';
  const pad = bin.length % 3;
  for (let i = 0; i < bin.length;) {
    if ((c0 = bin.charCodeAt(i++)) > 255 || (c1 = bin.charCodeAt(i++)) > 255 || (c2 = bin.charCodeAt(i++)) > 255)
      throw new TypeError('invalid character found');
    u32 = (c0 << 16) | (c1 << 8) | c2;
    asc += b64chs[(u32 >> 18) & 63] + b64chs[(u32 >> 12) & 63] + b64chs[(u32 >> 6) & 63] + b64chs[u32 & 63];
  }

  return pad ? asc.slice(0, pad - 3) + '==='.slice(Math.max(0, pad)) : asc;
};

const atobPolyfill = asc => {
  // console.log('polyfilled');
  asc = asc.replace(/\s+/g, '');
  asc += '=='.slice(2 - (asc.length & 3));
  let u24;
  let bin = [];
  let r1;
  let r2;
  for (let i = 0; i < asc.length;) {
    u24 =
      (b64tab[asc.charAt(i++)] << 18) |
      (b64tab[asc.charAt(i++)] << 12) |
      ((r1 = b64tab[asc.charAt(i++)]) << 6) |
      (r2 = b64tab[asc.charAt(i++)]);

    if (r1 === 64) {
      bin.push((u24 >> 16) & 255);
    } else if (r2 === 64) {
      bin.push((u24 >> 16) & 255, (u24 >> 8) & 255);
    } else {
      bin.push((u24 >> 16) & 255, (u24 >> 8) & 255, u24 & 255);
    }
  }

  return bin;
};

const txt = await fs.readFile('input.txt', 'utf-8');
const password = '12345678';

const txt2 = txt.replace(/TENDERMINT PRIVATE KEY/g, 'PGP PRIVATE KEY BLOCK');
console.log(txt2);

const res = await openpgp.unarmor(txt2);
console.log(res);

const regexp = /salt: ([\dA-Z]*)$/g;
const saltFound = res.headers.find(item => item.match(regexp));
const salt = regexp.exec(saltFound)?.[1];
const saltBytes = fromHex(salt);
const saltString = String.fromCharCode(...saltBytes);

// Add prefix for format required on bcrypt library
const formattedSalt = `$2a$10$${btoaPolyfill(saltString)}`;

const key = await bcrypt.hash(password, formattedSalt);

// Remove prefix for getting the generated intermediate key
const keyBytes = new Uint8Array(atobPolyfill(key.slice(7)));

// Cut only the required sizes for nonce and key
const finalResult = nacl.secretbox.open(res.data, res.data.slice(0, 24), keyBytes.slice(0, 32));
console.log(finalResult);
