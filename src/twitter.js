const nacl = require('tweetnacl')
const secp256k1 = require('secp256k1')
const axios = require('axios')
const uuid = require('uuid')

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
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  // nacl.secretbox.keyLength = secret.length
  const box = nacl.secretbox(toBytes(Buffer.from(message).toString('hex')), nonce, toBytes(secret).slice(1))
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

/**
 * Example encryption
  const publicKey1 = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey))) const publicKey2 = fromBytes(secp256k1.publicKeyCreate(toBytes(key2.privateKey)))
  console.log(publicKey1, publicKey2)
  const message = 'hello'
  const enc = encrypt(message, key1.privateKey, publicKey2)
  console.log(enc)
  const dec = decrypt(enc, key2.privateKey, publicKey1)
  console.log(Buffer.from(dec).toString())
 **/

async function loadPublicKey(handle) {
  const { data } = await axios(`https://server.cryptweet.now.sh/publickey/${handle.replace('@', '')}`)
  return data.publicKey
}

function editorElement() {
  const [ editor ] = document.getElementsByClassName('public-DraftEditor-content')
  return editor
}

function setCurrentTweet(text) {
  const [ editor ] = document.getElementsByClassName('public-DraftEditor-content')
  if (!editor) return
  editor.innerText = text
}

function addButton() {
  const [ toolbar ] = document.querySelectorAll('[data-testid="toolBar"]')
  if (!toolbar) return
  const button = document.createElement('div')
  button.setAttribute('style', `
    background-color: green;
    display: flex;
    color: white;
  `)
  button.addEventListener('click', async () => {
    const tweet = editorElement().innerText
    // garbage regex, TODO: refactor
    const handleRegex = /@[a-zA-Z0-9.]+/g
    const mention = tweet.match(handleRegex)
    if (mention.length === 0) return
    const user = mention[0]
    console.log(user)
    try {
      const publicKey = await loadPublicKey(user)
      const msg = encrypt(tweet, key1.privateKey, publicKey.replace('0x', ''))
      const hexmsg = Buffer.from(msg).toString('hex')
      const enc = document.getElementById('enc_editor')
      const prefix = '<'
      const suffix = '>'
      const fullMessage = `${user} ${hexmsg}`
      const chunks = []
      const chunkLength = 280
      let i = 0
      let chunkIndex = 0
      console.log(hexmsg)
      for (;;) {
        if (i > hexmsg.length) break
        if (i === 0) {
          // add the user handle
          const str = `${user} ${hexmsg.length} ${chunkIndex}${prefix}`
          i = chunkLength - str.length - suffix.length
          chunks.push(str+hexmsg.slice(0, i)+suffix)
          chunkIndex++
          continue
        }
        const newI = i + chunkLength - suffix.length - prefix.length - chunkIndex.toString().length
        chunks.push(chunkIndex.toString() + prefix + hexmsg.slice(i, newI) + suffix)
        i = newI
        chunkIndex++
      }
      enc.innerHTML = chunks.join('<br /><br />')
    } catch (err) {
      console.log(err)
    }
  })
  button.innerText = 'Encrypt'
  toolbar.appendChild(button)
}

if (!document.getElementById('enc_editor')) {
  const enc = document.createElement('div')
  enc.setAttribute('id', 'enc_editor')
  enc.setAttribute('style', `
    position: absolute;
    right: 0px;
    top: 0px;
    min-height: 50px;
    min-width: 50px;
    max-width: 250px;
    background-color: white;
    word-wrap: break-word;
    white-space: pre-wrap;
  `)
  document.body.appendChild(enc)
}

;(async () => {
  try {
    addButton()
    // const _key1 = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey)))
    // console.log(_key1)
    // console.log(await loadPublicKey('wehaveanstd'))
  } catch (err) {
    console.log(err)
  }
})()
