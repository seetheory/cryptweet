const nacl = require('tweetnacl')
const secp256k1 = require('secp256k1')

const key1 = {
  privateKey: '99d6a84550b53c5b4c57907e038578497cfb274afc1bb51cca6f32e45f311c7e',
  address: '0x4AE9DA4C61acb12772F4F2699a1e2B4d847AA61C',
}

const key2 = {
  privateKey: 'f8d32fe360f3be243d5a7ae41c3140cfd71dc0e10deb0c09fc51260b77c11db2',
  address: '0x30c649cDAa9E6E84E2829764a0dE83c0F92D7235',
}

const evenPad = key => key.length % 2 === 0 ? key : `0${key}`
const toBytes = (hex, base = 16) =>
  new Uint8Array(evenPad(hex).match(/.{1,2}/g).map(byte => parseInt(byte, base)))
const fromBytes = (bytes, base = 16) =>
  Array.prototype.map.call(bytes, (byte) => {
    return `0${byte.toString(base)}`.slice(-2)
  }).join('')

function encrypt(message, privateKey, publicKey) {
  const secret = sharedSecret(privateKey, publicKey)
  console.log(toBytes(secret).length)
  console.log(nacl.secretbox.keyLength)
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  // nacl.secretbox.keyLength = secret.length
  const box = nacl.secretbox(toBytes(Buffer.from(message).toString('hex')), nonce, toBytes(secret).slice(1))
  console.log(fromBytes(box))
  return JSON.stringify({
    m: fromBytes(box),
    n: fromBytes(nonce)
  })
}

function decrypt(boxJson, privateKey, publicKey) {
  const secret = sharedSecret(privateKey, publicKey)
  const box = JSON.parse(boxJson)
  console.log(toBytes(box.m))
  return nacl.secretbox.open(toBytes(box.m), toBytes(box.n), toBytes(secret).slice(1))
}

function sharedSecret(privateKey, publicKey) {
  const hashfn = (x, y) => {
    const pubKey = new Uint8Array(33)
    pubKey[0] = (y[31] & 1) === 0 ? 0x02 : 0x03
    pubKey.set(x, 1)
    return pubKey
  }
  const privateBytes = toBytes(privateKey)
  const publicBytes = typeof publicKey === 'string' ? toBytes(publicKey) : publicKey
  return secp256k1.ecdh(publicBytes, privateBytes, { hashfn }, Buffer.alloc(33)).toString('hex')
}

const publicKey1 = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey)))
const publicKey2 = fromBytes(secp256k1.publicKeyCreate(toBytes(key2.privateKey)))
console.log(publicKey1, publicKey2)
const message = 'hello'
const enc = encrypt(message, key1.privateKey, publicKey2)
console.log(enc)
const dec = decrypt(enc, key2.privateKey, publicKey1)
console.log(Buffer.from(dec).toString())
