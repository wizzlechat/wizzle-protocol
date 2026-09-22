import { test } from 'node:test';
import assert from 'node:assert/strict';
import { concat, equal, fromB64Url, fromHex, readU32, readU64, toB64Url, utf8, fromUtf8, writeU32, writeU64 } from '../src/bytes.ts';

test('base64url round trips every length', () => {
  for (let n = 0; n < 40; n++) {
    const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 255);
    assert.deepEqual(fromB64Url(toB64Url(b)), b);
  }
  assert.equal(toB64Url(fromHex('fbff')), '-_8');
});

test('base64url rejects bad input', () => {
  assert.throws(() => fromB64Url('abc+'));
  assert.throws(() => fromB64Url('a'));
});

test('integers round trip big endian', () => {
  assert.equal(readU32(writeU32(0xdeadbeef)), 0xdeadbeef);
  assert.equal(readU64(writeU64(1n << 62n)), 1n << 62n);
  assert.deepEqual(writeU64(1n), fromHex('0000000000000001'));
});

test('concat, equal, utf8', () => {
  assert.deepEqual(concat(fromHex('01'), fromHex('0203')), fromHex('010203'));
  assert.ok(equal(fromHex('0102'), fromHex('0102')));
  assert.ok(!equal(fromHex('0102'), fromHex('0103')));
  assert.equal(fromUtf8(utf8('wizzle')), 'wizzle');
});
