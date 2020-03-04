const nacl = require('tweetnacl')
const secp256k1 = require('secp256k1')
const axios = require('axios')
const generate = require('nanoid/generate')
const hash = require('hash.js')
const ethers = require('ethers')

// window.localStorage.removeItem('cryptweet_private_key')
let activePrivateKey = window.localStorage.getItem('cryptweet_private_key')
function activePublicKey() {
  if (!activePrivateKey) return null
  return '0x' + fromBytes(secp256k1.publicKeyCreate(toBytes(activePrivateKey)))
}

const buttonStyle = `
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, "Helvetica Neue", sans-serif;
  font-weight: 700;
  font-size: 15px;
  color: white;
  cursor: pointer;
`

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
function encrypt(message, privateKey, publicKey) {
  const secret = toBytes(sharedSecret(privateKey, publicKey)).slice(0, nacl.secretbox.keyLength)
  // console.log('encrypt secret:', fromBytes(secret))
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  // nacl.secretbox.keyLength = secret.length
  const box = nacl.secretbox(toBytes(Buffer.from(message).toString('hex')), nonce, secret)
  return JSON.stringify({
    m: fromBytes(box),
    n: fromBytes(nonce)
  })
}

function decrypt(boxJson, privateKey, publicKey) {
  const secret = toBytes(sharedSecret(privateKey, publicKey)).slice(0, nacl.secretbox.keyLength)
  // console.log('decrypt secret:', fromBytes(secret))
  const box = JSON.parse(boxJson)
  return nacl.secretbox.open(toBytes(box.m), toBytes(box.n), secret)
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
  const hashedSecret = hash.sha256().update(secret).digest('hex')
  return hashedSecret
}

async function loadPublicKey(handle) {
  const { data } = await axios(`https://server.cryptweet.now.sh/publickey/${handle.replace('@', '')}`)
  return data.publicKey
}

function editorElement() {
  const [ editor ] = document.getElementsByClassName('public-DraftEditor-content')
  return editor
}

async function cryptweet() {
  const enc = document.getElementById('enc_editor')
  const children = [...enc.children]
  for (const child of children) {
    if (child.className === 'chunk') child.remove()
  }
  const tweet = editorElement().innerText
  // garbage regex, TODO: refactor
  const handleRegex = /@[a-zA-Z0-9.]+/g
  const mention = tweet.match(handleRegex)
  if (mention.length === 0) return
  const user = mention[0]
  try {
    const publicKey = await loadPublicKey(user)
    const content = tweet.slice(user.length).trim()
    const msg = encrypt(content, activePrivateKey, publicKey)
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
        const str = `${user} ${activePublicKey()}${id}${prefix}`
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
    const header = document.createElement('div')
    header.setAttribute('class', 'chunk')
    header.setAttribute('style', `
      padding: 10px;
      ${buttonStyle}
      color: black;
    `)
    header.innerText = 'Copy each of the following into a chain of tweets:'
    enc.appendChild(header)
    for (const chunk of final) {
      const chunkContainer = document.createElement('div')
      chunkContainer.setAttribute('class', 'chunk')
      chunkContainer.setAttribute('style', `
        display: flex;
        flex-direction: column;
        align-items: center;
      `)
      const chunkText = document.createElement('textarea')
      chunkText.setAttribute('readonly', 'true')
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

function createKey() {
  if (activePrivateKey) {
    //confirm action
  }
  function generatePrivateKey() {
    for (;;) {
      const key = nacl.randomBytes(32)
      if (secp256k1.privateKeyVerify(key)) return key
    }
  }
  activePrivateKey = fromBytes(generatePrivateKey())
  window.localStorage.setItem('cryptweet_private_key', activePrivateKey)
  createSidebar()
}

function createSidebar() {
  const editor = document.getElementById('enc_editor')
  if (editor) editor.remove()
  const enc = document.createElement('div')
  enc.setAttribute('id', 'enc_editor')
  enc.setAttribute('style', `
    position: fixed;
    right: 0px;
    bottom: 0px;
    min-height: 50px;
    width: 250px;
    background-color: white;
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
    align-items: center;
    padding: 2px;
  `)
  document.body.appendChild(enc)
  const publicKeyDiv = document.createElement('div')
  publicKeyDiv.setAttribute('style', `
    ${buttonStyle}
    color: black;
    margin-bottom: 10px;
    word-wrap: break-word;
    white-space: pre-wrap;
    max-width: 100%;
  `)
  const currentPublicKey = activePrivateKey ?
    activePublicKey() :
    'No public key, create or load an identity'
  publicKeyDiv.innerText = currentPublicKey
  const buttonContainer = document.createElement('div')
  buttonContainer.setAttribute('style', `
    display: flex;
  `)
  const saveKeyButton = document.createElement('div')
  saveKeyButton.setAttribute('style', `
    height: 30px;
    line-height: 30px;
    background-color: purple;
    ${buttonStyle}
    text-align: center;
    border-radius: 9999px;
    padding-left: 8px;
    padding-right: 8px;
    margin-right: 4px;
    margin-left: 4px;
  `)
  saveKeyButton.addEventListener('click', () => {
    const wallet = new ethers.Wallet(activePrivateKey)
    console.log(wallet)
    const el = document.createElement('a')
    el.setAttribute('href', `data:text/plain;charset=utf-8,${encodeURIComponent(wallet.privateKey)}`)
    el.setAttribute('download', 'cryptweet_private_key.txt')
    el.style.display = 'none'
    document.body.appendChild(el)
    el.click()
    el.remove()
  })
  saveKeyButton.innerText = 'Save Key'
  const newKeyButton = document.createElement('div')
  newKeyButton.setAttribute('style', `
    height: 30px;
    line-height: 30px;
    background-color: green;
    ${buttonStyle}
    text-align: center;
    border-radius: 9999px;
    padding-left: 8px;
    padding-right: 8px;
    margin-right: 4px;
    margin-left: 4px;
  `)
  newKeyButton.innerText = 'New Key'
  newKeyButton.addEventListener('click', createKey)
  buttonContainer.appendChild(newKeyButton)
  buttonContainer.appendChild(saveKeyButton)
  const titleSpan = document.createElement('span')
  titleSpan.innerText = 'cryptweet'
  titleSpan.setAttribute('style', `
    ${buttonStyle}
    margin-bottom: 10px;
    color: black;
    font-size: 25px;
  `)
  enc.appendChild(titleSpan)
  enc.appendChild(publicKeyDiv)
  enc.appendChild(buttonContainer)
}
setTimeout(createSidebar, 200)

/**
 * Every 2 seconds add buttons if needed
 **/
setInterval(() => {
  addButtons()
}, 2000)

/**
 * Every 2 seconds look for messages to decrypt
 **/
setInterval(() => {
  const composeElements = document.getElementsByClassName('public-DraftEditor-content')
  const chunkRegex = /(0x[0-9a-fA-F]{66})?(\d\d)(\d\d)([a-z]{10})<([0-9a-fA-F]+)>/g
  let match = chunkRegex.exec(document.body.innerText)
  const chunksById = {}
  while (match !== null) {
    const [ full, publicKey, index, total, id, data ] = match
    if (!chunksById[id]) {
      chunksById[id] = []
    }
    chunksById[id].push({ publicKey, index, total, id, data, full })
    match = chunkRegex.exec(document.body.innerText)
  }
  for (const id of Object.keys(chunksById)) {
    const chunks = chunksById[id]
    if (chunks.length !== +chunks[0].total) continue
    chunks.sort((a, b) => a.index - b.index)
    const fullData = chunks.map(c => c.data).join('').replace('<', '').replace('>', '')
    const data = Buffer.from(fullData, 'hex').toString('utf8')
    const publicKey = chunks[0].publicKey
    const decrypted = decrypt(data, activePrivateKey, publicKey)
    if (!decrypted) continue
    const text = Buffer.from(decrypted).toString()
    const xpath = `//span[contains(text(), '${chunks[0].data}')]`
    const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue
    let editing = false
    for (const e of composeElements) {
      if (e.contains(element)) editing = true
    }
    // don't modify if composing a tweet
    if (editing) continue
    element.innerText = ` DECRYPTED:` + element.innerText.replace(chunks[0].full, text)
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

function addButton(element) {
  const button = document.createElement('div')
  button.setAttribute('class', 'cryptweet_encrypt_button')
  button.setAttribute('style', `
    background-color: green;
    height: 39px;
    min-width: 62.8px;
    display: flex;
    border-radius: 9999px;
    align-items: center;
    justify-content: center;
    margin-top: 10px;
    ${buttonStyle}
  `)
  const textContainer = document.createElement('div')
  textContainer.setAttribute('style', `
    display: flex;
    margin: 4px;
    padding-left: 10px;
    padding-right: 10px;
  `)
  textContainer.innerText = 'Crypt'
  button.appendChild(textContainer)
  element.insertBefore(button, element.lastChild)
  button.addEventListener('click', cryptweet)
}

// * Example encryption
function test() {
  const key1 = {
    privateKey: '99d6a84550b53c5b4c57907e038578497cfb274afc1bb51cca6f32e45f311c7e',
    address: '0x4AE9DA4C61acb12772F4F2699a1e2B4d847AA61C',
  }
  const key2 = {
    privateKey: 'f8d32fe360f3be243d5a7ae41c3140cfd71dc0e10deb0c09fc51260b77c11db2',
    address: '0x30c649cDAa9E6E84E2829764a0dE83c0F92D7235',
  }
  try {
    const publicKey1 = fromBytes(secp256k1.publicKeyCreate(toBytes(key1.privateKey)))
    const publicKey2 = fromBytes(secp256k1.publicKeyCreate(toBytes(key2.privateKey)))
    console.log(publicKey1, publicKey2)
    const message = 'hello'
    const enc = encrypt(message, key1.privateKey, publicKey2)
    console.log(enc)
    const dec = decrypt(enc, key2.privateKey, publicKey1)
    console.log('message:', Buffer.from(dec).toString())
  } catch (err) {
    console.log('Error testing:', err)
  }
}
// setTimeout(test, 2000)
