const nacl = require('tweetnacl')
const secp256k1 = require('secp256k1')
const axios = require('axios')
const generate = require('nanoid/generate')
const Web3 = require('web3')

const key1 = {
  privateKey: '99d6a84550b53c5b4c57907e038578497cfb274afc1bb51cca6f32e45f311c7e',
  address: '0x4AE9DA4C61acb12772F4F2699a1e2B4d847AA61C',
}

const key2 = {
  privateKey: 'f8d32fe360f3be243d5a7ae41c3140cfd71dc0e10deb0c09fc51260b77c11db2',
  address: '0x30c649cDAa9E6E84E2829764a0dE83c0F92D7235',
}

 // * Example encryption
function test() {
  const publicKey1 = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey)))
  const publicKey2 = fromBytes(secp256k1.publicKeyCreate(toBytes(key2.privateKey)))
  console.log(publicKey1, publicKey2)
  const message = 'hello'
  const enc = encrypt(message, key1.privateKey, publicKey2)
  console.log(enc)
  const dec = decrypt(enc, key2.privateKey, publicKey1)
  console.log(Buffer.from(dec).toString())
}

/**
 * Uint8Array <-> hex helpers
 **/
const evenPad = key => key.length % 2 === 0 ? key : `0${key}`
const toBytes = (hex, base = 16) =>
  new Uint8Array(evenPad(hex).match(/.{1,2}/g).map(byte => parseInt(byte, base)))
const fromBytes = (bytes, base = 16) =>
  Array.prototype.map.call(bytes, (byte) => {
    return `0${byte.toString(base)}`.slice(-2)
  }).join('')

/**
 * Encrypt, decrypt, shared secret
 **/
{
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
    const publicBytes = typeof publicKey === 'string' ?
      toBytes(publicKey.replace('0x', '')) :
      publicKey
    const secret = secp256k1.ecdh(publicBytes, privateBytes, { hashfn }, Buffer.alloc(33)).toString('hex')
    return secret
  }
}

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

function addButton(element) {
  const button = document.createElement('div')
  button.setAttribute('class', 'cryptweet_encrypt_button')
  button.setAttribute('style', `
    background-color: green;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, "Helvetica Neue", sans-serif;
    font-weight: 700;
    font-size: 15px;
    height: 39px;
    min-width: 62.8px;
    color: white;
    display: flex;
    border-radius: 9999px;
    cursor: pointer;
    align-items: center;
    justify-content: center;
    margin-top: 10px;
  `)
  const textContainer = document.createElement('div')
  textContainer.setAttribute('style', `
    display: flex;
    margin: 4px;
  `)
  textContainer.innerText = 'Crypt'
  button.appendChild(textContainer)
  element.appendChild(button)
  button.addEventListener('click', cryptweet)
}

async function cryptweet() {
  const enc = document.getElementById('enc_editor')
  while (enc.lastChild) enc.lastChild.remove()
  const tweet = editorElement().innerText
  // garbage regex, TODO: refactor
  const handleRegex = /@[a-zA-Z0-9.]+/g
  const mention = tweet.match(handleRegex)
  if (mention.length === 0) return
  const user = mention[0]
  try {
    const publicKey = await loadPublicKey(user)
    const content = tweet.slice(user.length).trim()
    const msg = encrypt(content, key1.privateKey, publicKey)
    const hexmsg = Buffer.from(msg).toString('hex')
    const prefix = '<'
    const suffix = '>'
    const chunks = []
    const chunkLength = 280
    let i = 0
    let chunkIndex = 0
    // the id prefix will store the total chunks and current chunk index
    const id = '0000' + generate('abcdefghijklmnopqrstuvwxyz', 10)
    // Best way to chunk a binary message in tweets with the intent of
    // traversing the dom to retrieve (e.g. regex/keywords)
    for (;;) {
      if (i >= hexmsg.length) break
      if (i === 0) {
        // add the user handle
        const str = `${user} ${id}${prefix}`
        i = chunkLength - str.length - suffix.length
        chunks.push(
          str + hexmsg.slice(0, i) + suffix
        )
        chunkIndex++
        continue
      }
      const newI = Math.min(
        i + chunkLength - (suffix.length + prefix.length + id.length),
        hexmsg.length
      )
      chunks.push(
        id + prefix + hexmsg.slice(i, newI) + suffix
      )
      i = newI
      chunkIndex++
    }
    const final = chunks.map((chunk, index) => {
      return chunk.replace('0000', `${index < 10 ? '0' : ''}${index}${chunks.length < 10 ? '0' : ''}${chunks.length}`)
    })
    for (const chunk of final) {
      const chunkContainer = document.createElement('div')
      chunkContainer.setAttribute('style', `
        display: flex;
        flex-direction: column;
        align-items: center;
      `)
      const chunkText = document.createElement('textarea')
      chunkText.setAttribute('style', `
        padding: 2px;
        max-width: 230px;
        word-wrap: break-word;
        white-space: pre-wrap;
      `)
      chunkText.value = chunk
      const copyButton = document.createElement('div')
      copyButton.setAttribute('style', `
        min-height: 20px;
        background-color: black;
        color: white;
        border-radius: 4px;
        padding: 2px;
        cursor: pointer;
      `)
      copyButton.addEventListener('click', () => {
        chunkText.select()
        document.execCommand('copy')
        copyButton.innerText = 'copied!'
      })
      copyButton.innerText = 'copy'
      chunkContainer.appendChild(chunkText)
      chunkContainer.appendChild(copyButton)
      enc.appendChild(chunkContainer)
    }
  } catch (err) {
    console.log(err)
  }
}

if (!document.getElementById('enc_editor')) {
  const enc = document.createElement('div')
  enc.setAttribute('id', 'enc_editor')
  enc.setAttribute('style', `
    position: fixed;
    right: 0px;
    top: 30px;
    min-height: 50px;
    min-width: 100px;
    max-width: 250px;
    background-color: white;
  `)
  document.body.appendChild(enc)
  const publicKeyButton = document.createElement('div')
  publicKeyButton.setAttribute('style', `
    position: fixed;
    right: 0px;
    top: 0px;
    height: 30px;
    background-color: purple;
  `)
  publicKeyButton.addEventListener('click', () => {
    console.log(window.ethereum)
  })
  publicKeyButton.innerText = 'Copy My Key'
  document.body.appendChild(publicKeyButton)
}

/**
 * Every 2 seconds add buttons if needed
 **/
setInterval(() => {
  addButtons()
}, 2000)

/**
 * Every 5 seconds look for messages to decrypt
 **/
setInterval(() => {
  const composeElements = document.getElementsByClassName('public-DraftEditor-content')
  const chunkRegex = /(\d\d)(\d\d)([a-z]{10})<([0-9a-fA-F]+)>/g
  let match = chunkRegex.exec(document.body.innerText)
  const chunksById = {}
  while (match !== null) {
    const [ full, index, total, id, data ] = match
    if (!chunksById[id]) {
      chunksById[id] = []
    }
    chunksById[id].push({ index, total, id, data, full })
    match = chunkRegex.exec(document.body.innerText)
  }
  for (const id of Object.keys(chunksById)) {
    const chunks = chunksById[id]
    if (chunks.length !== +chunks[0].total) continue
    chunks.sort((a, b) => a.index - b.index)
    const fullData = chunks.map(c => c.data).join('').replace('<', '').replace('>', '')
    const data = Buffer.from(fullData, 'hex').toString('utf8')
    const publicKey = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey)))
    const decrypted = decrypt(data, key2.privateKey, publicKey)
    if (!decrypted) continue
    const text = Buffer.from(decrypted).toString()
    const xpath = `//span[contains(text(), '${chunks[0].data}')]`
    let editing = false
    for (const e of composeElements) {
      if (e.contains(element)) editing = true
    }
    // don't modify if composing a tweet
    if (editing) continue
    const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
    element.innerText = ` DECRYPTED: ` + element.innerText.replace(chunks[0].full, text)
  }
}, 2000)

function addButtons() {
  const editFields = document.querySelectorAll('[data-testid="toolBar"]')
  if (editFields.length === 0) return
  (() => {
    for (const field of editFields) {
      for (const child of field.children) {
        if (child.className === 'cryptweet_encrypt_button') return
      }
      addButton(field)
    }
  })()
}
