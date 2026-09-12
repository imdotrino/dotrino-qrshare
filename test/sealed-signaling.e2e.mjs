/**
 * Prueba de punta a punta del SELLADO de la señalización (CONVENCIONES §4.1).
 *
 * Dos navegadores: uno muestra el QR y el otro lo ESCANEA de verdad —la imagen se
 * decodifica con jsQR, no se copia la URL del DOM— y se transfiere un archivo. Lo
 * que se comprueba no es que funcione, sino:
 *
 *   · que por el socket NO viaja ningún SDP ni ICE legible, en las DOS direcciones
 *     (sellar solo de salida se lo salta quien acepte texto en claro)
 *   · que la transferencia llega entera y byte a byte igual
 *   · que el fallo es distinguible: sin la llave del otro lado se para con
 *     `code: 'unsealed'`, y no se cae a mandar en claro
 *
 * Cómo correrla:
 *
 *   npm install && npx playwright install chromium
 *   npm run serve &                 # sirve el repo en http://127.0.0.1:8788/
 *   npm run test:e2e                # o QRSHARE_BASE=https://qrshare.dotrino.com/
 *
 * Habla con el proxio de PRODUCCIÓN (`wss://proxy.dotrino.com`): hace falta red.
 */
import { chromium } from 'playwright'
import { createRequire } from 'node:module'
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import path from 'node:path'

const require = createRequire(import.meta.url)
const jsQR = require('jsqr').default || require('jsqr')
const { PNG } = require('pngjs')

const BASE = process.env.QRSHARE_BASE || 'http://127.0.0.1:8788/'
const OUT = process.env.OUT_DIR || path.join(tmpdir(), 'qrshare-e2e')
mkdirSync(OUT, { recursive: true })

const results = []
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${name}${detail ? ' — ' + detail : ''}`)
}

/** Graba TODO lo que entra y sale por el WebSocket, antes de que cargue la app. */
const RECORDER = () => {
  window.__frames = { out: [], in: [] }
  const NativeWS = window.WebSocket
  const Patched = function (url, protocols) {
    const ws = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols)
    const send = ws.send.bind(ws)
    ws.send = (data) => { try { window.__frames.out.push(String(data)) } catch (_) {} ; return send(data) }
    ws.addEventListener('message', (e) => { try { window.__frames.in.push(String(e.data)) } catch (_) {} })
    return ws
  }
  Patched.prototype = NativeWS.prototype
  for (const k of ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED']) Patched[k] = NativeWS[k]
  window.WebSocket = Patched
}

const browser = await chromium.launch()

async function newPage (tag) {
  const ctx = await browser.newContext({ acceptDownloads: true })
  await ctx.addInitScript(RECORDER)
  const page = await ctx.newPage()
  page.on('console', (m) => { if (m.text().includes('[qrshare]')) console.log(`  (${tag}) ${m.text()}`) })
  page.on('pageerror', (e) => console.log(`  (${tag}) PAGEERROR ${e.message}`))
  return { ctx, page }
}

// ---------- 1. el emisor: archivo, QR ----------
const payload = randomBytes(300 * 1024)          // 300 KB: varios trozos, no un caso de juguete
const srcPath = path.join(OUT, 'muestra.bin')
writeFileSync(srcPath, payload)
const srcHash = createHash('sha256').update(payload).digest('hex')

const A = await newPage('emisor')
await A.page.goto(BASE)
await A.page.waitForFunction(() => window.qrshareApp?.client?.token && window.qrshareApp.publickey, null, { timeout: 30000 })
check('el emisor conecta por el pilar y se identifica', true)

await A.page.setInputFiles('#fileInput', srcPath)
await A.page.click('[data-testid="share"]')
await A.page.waitForSelector('#qrContainer svg', { timeout: 15000 })

const shownUrl = (await A.page.textContent('[data-testid="pairing-url"]')).trim()
check('el enlace va en el #fragment (no llega al servidor)', shownUrl.includes('#') && !shownUrl.includes('?'), shownUrl.length + ' caracteres')

// ---------- 2. el receptor ESCANEA el QR ----------
const qrPng = await A.page.locator('#qrContainer').screenshot({ path: path.join(OUT, 'qr.png') })
const png = PNG.sync.read(qrPng)
const decoded = jsQR(new Uint8ClampedArray(png.data), png.width, png.height)
check('el QR se lee con un decodificador de verdad', !!decoded && decoded.data === shownUrl,
  decoded ? `${decoded.data.length} bytes en el QR, versión ${decoded.version}` : 'no se pudo decodificar')
const scannedUrl = decoded ? decoded.data : shownUrl

const B = await newPage('receptor')
const downloadPromise = B.page.waitForEvent('download', { timeout: 120000 })
await B.page.goto(scannedUrl)
await B.page.waitForFunction(() => window.qrshareApp?.client?.token, null, { timeout: 30000 })
check('el receptor entra por el QR y se identifica', true)

// ---------- 3. la transferencia entera ----------
const download = await downloadPromise
const gotPath = path.join(OUT, 'recibido.bin')
await download.saveAs(gotPath)
const got = readFileSync(gotPath)
check('el archivo llega entero y byte a byte igual',
  got.length === payload.length && createHash('sha256').update(got).digest('hex') === srcHash,
  `${got.length} de ${payload.length} bytes`)

await B.page.waitForFunction(
  () => /completada/i.test(document.querySelector('[data-testid="receiver-status"]')?.textContent || ''),
  null, { timeout: 30000 })
check('el receptor la da por completada', true)

// ---------- 4. nada en claro, en las DOS direcciones ----------
const LEAKS = [
  ['SDP', /"sdp"|v=0|o=- |m=application/],
  ['ICE', /"candidate"|typ host|typ srflx|a=candidate/],
  ['hello con llaves', /"type"\s*:\s*"hello"/],
]

function auditar (tag, frames) {
  const dirigidos = []
  for (const raw of frames) {
    let msg
    try { msg = JSON.parse(raw) } catch (_) { continue }
    const esDirigido = msg.to_publickey || msg.to || (msg.type === 'message' && msg.message !== undefined)
    if (!esDirigido) continue
    let inner = msg.message
    if (typeof inner === 'string') { try { inner = JSON.parse(inner) } catch (_) {} }
    dirigidos.push({ raw, inner })
  }
  const sinSellar = dirigidos.filter(({ inner }) =>
    !(inner && inner.v === 1 && inner.sealed && inner.sealed.ct && inner.sealed.epk))
  check(`${tag}: todo mensaje dirigido va sellado`, dirigidos.length > 0 && sinSellar.length === 0,
    `${dirigidos.length} dirigidos, ${sinSellar.length} sin sellar`)
  for (const [nombre, re] of LEAKS) {
    const sucios = frames.filter((f) => re.test(f))
    check(`${tag}: nada de ${nombre} legible por el socket`, sucios.length === 0,
      sucios.length ? sucios[0].slice(0, 160) : `${frames.length} tramas revisadas`)
  }
  return dirigidos.length
}

const framesA = await A.page.evaluate(() => window.__frames)
const framesB = await B.page.evaluate(() => window.__frames)
const dirA = auditar('emisor → proxio', framesA.out)
const dirB = auditar('receptor → proxio', framesB.out)
auditar('proxio → emisor', framesA.in)
auditar('proxio → receptor', framesB.in)
check('los dos lados hablaron de verdad', dirA > 0 && dirB > 0, `${dirA} salidas del emisor, ${dirB} del receptor`)

// ---------- 5. el fallo es distinguible ----------
const faltaLlave = await A.page.evaluate(async () => {
  const a = window.qrshareApp
  try {
    await a.client.sendSealed([a.peer.publickey], { type: 'ice' }, {})   // sin peerEncPub
    return { threw: false }
  } catch (e) { return { threw: true, code: e.code, message: e.message } }
})
check('sin la llave del otro lado falla con code "unsealed"', faltaLlave.threw && faltaLlave.code === 'unsealed',
  JSON.stringify(faltaLlave))

const enClaro = await A.page.evaluate(async () => {
  const a = window.qrshareApp
  try {
    a.client.sendByPubkey([a.peer.publickey], { type: 'ice', candidate: 'typ host' })
    return { threw: false }
  } catch (e) { return { threw: true, code: e.code } }
})
check('requireSealed se niega a mandar en claro', enClaro.threw && enClaro.code === 'unsealed', JSON.stringify(enClaro))

const sinPeer = await A.page.evaluate(async () => {
  const a = window.qrshareApp
  const guardado = a.peer
  a.peer = null
  try {
    await a.sendSignal({ type: 'ice' })
    return { threw: false }
  } catch (e) { return { threw: true, code: e.code } } finally { a.peer = guardado }
})
check('la app tampoco manda sin emparejar (code "unsealed")', sinPeer.threw && sinPeer.code === 'unsealed', JSON.stringify(sinPeer))

// De ENTRADA: un tercero manda texto en claro a la pubkey del emisor. Tiene que
// caer, y tiene que decirlo — sellar solo de salida no sirve de nada (§4.1).
const pubA = await A.page.evaluate(() => window.qrshareApp.publickey)
await A.page.evaluate(() => {
  window.__unsealed = []
  window.__entregados = []
  const c = window.qrshareApp.client
  c.on('error', (e) => { if (e && e.type) window.__unsealed.push(e) })
  c.on('message', (from, payload) => window.__entregados.push(payload))
})
const C = await newPage('intruso')
await C.page.goto(BASE)
await C.page.evaluate(async (pub) => {
  await new Promise((resolve, reject) => {
    const ws = new WebSocket('wss://proxy.dotrino.com')
    ws.onopen = () => {}
    ws.onerror = reject
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data)
      if (m.type === 'connected') {
        ws.send(JSON.stringify({
          to_publickey: [pub],
          message: JSON.stringify({ type: 'offer', sdp: { type: 'offer', sdp: 'v=0\r\na=candidate:1 1 udp 1 10.0.0.1 1 typ host\r\n' } })
        }))
        setTimeout(resolve, 2500)
      }
    }
  })
}, pubA)
await A.page.waitForTimeout(1500)
const entrada = await A.page.evaluate(() => ({ unsealed: window.__unsealed, entregados: window.__entregados }))
check('el texto en claro que ENTRA se descarta y se dice',
  entrada.unsealed.some((e) => e.type === 'unsealed' && e.reason === 'plaintext_rejected') && entrada.entregados.length === 0,
  JSON.stringify(entrada.unsealed))

await browser.close()

const fallos = results.filter((r) => !r.ok)
console.log(`\n${results.length - fallos.length}/${results.length} comprobaciones pasan`)
if (fallos.length) { console.log('FALLOS:'); for (const f of fallos) console.log(' -', f.name, f.detail) }
process.exit(fallos.length ? 1 : 0)
