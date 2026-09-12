/**
 * QRShare — transferencia de archivos P2P.
 *
 * DOS COSAS QUE ANTES ESTABAN MAL, Y SON LA MISMA LÍNEA DE CÓDIGO:
 *
 *   1. El transporte era un WebSocket casero contra el proxio, o sea el protocolo
 *      copiado dentro de la app. Ahora es el pilar del ecosistema,
 *      `@dotrino/proxy-client` (CLAUDE.md, «usar SIEMPRE las herramientas del
 *      ecosistema»).
 *   2. La señalización viajaba EN CLARO. El proxio enruta pero no cifra, así que
 *      una oferta SDP —que lleva las direcciones IP del aparato y dice con quién se
 *      conecta— la leía quien opera el proxio. Ahora va sellada extremo a extremo
 *      (CONVENCIONES §4.1): `sendSealed()` para salir y `requireSealed: true` para
 *      no aceptar nada en claro de vuelta.
 *
 * DE DÓNDE SALE LA LLAVE DEL OTRO LADO. Sellar exige la llave de cifrado del
 * destinatario, y el pilar no la descubre solo: se la tiene que dar la app. Aquí no
 * hace falta inventar nada, porque la app YA tiene un momento de emparejamiento que
 * no pasa por el proxio — el QR. Quien lo muestra pone ahí sus dos llaves públicas
 * (la de firma, que es por dónde se le escribe, y la de cifrado, que es con qué se
 * le sella); quien lo escanea las lee de la pantalla del otro.
 *
 * Y AL REVÉS, que es donde esto se rompe: el QR va en UNA dirección, así que el que
 * lo muestra no conoce al que escanea. Por eso la PRIMERA respuesta del que escanea
 * —ya sellada, porque él sí puede— lleva sus propias llaves dentro. A partir de ahí
 * los dos lados sellan y los dos lados rechazan lo que no venga sellado, que es lo
 * único que sirve: sellar solo de salida se lo salta quien acepte texto en claro.
 */
import {
  WebSocketProxyClient,
  makeEncKeypair,
  setSealingPrimitives,
  setKeypairStore,
  getPublicKeyJwk,
  signData,
} from 'https://cdn.jsdelivr.net/npm/@dotrino/proxy-client@0.19/+esm';
import * as contentCrypto from 'https://cdn.jsdelivr.net/npm/@dotrino/identity@0.89/content/+esm';

// El sellado del pilar es `wrapForMember`/`openWrap` de `@dotrino/identity/content`,
// la misma cripto de los secretos sellados del vault. Se inyecta aquí, en vez de
// dejar que el pilar la importe solo a mitad de un envío: así la dependencia está a
// la vista, pinada, y si falta se sabe al arrancar y no al mandar la oferta.
setSealingPrimitives(contentCrypto);

// LLAVE DE TRANSPORTE EFÍMERA, una por carga de página. El pilar la guardaría en
// localStorage, que es lo correcto para una app con identidad estable; aquí no: un
// traspaso empareja una vez por QR y se acaba, y una llave persistente convertiría
// cada visita en la misma identidad reconocible ante el proxio sin que nadie lo
// pida. Sigue siendo la llave del pilar, no una propia: solo cambia dónde se guarda.
let memoryKeypair = null;
setKeypairStore({
  get: async () => memoryKeypair,
  set: async (pair) => { memoryKeypair = pair; },
});

const PROXY_URL = 'wss://proxy.dotrino.com';

/** Versión del código de emparejamiento que viaja en el QR. */
const PAIRING_VERSION = '1';

/** Una coordenada de P-256 en base64url: 32 bytes → 43 caracteres. */
const COORD = /^[A-Za-z0-9_-]{43}$/;

/** Error con un `code` estable: el contrato es el code, nunca la frase (§8.1). */
function errorWithCode (message, code) {
  return Object.assign(new Error(message), { code });
}

/**
 * La forma canónica de una llave pública P-256, y la MISMA en los dos lados.
 *
 * El proxio enruta comparando la cadena del JWK tal cual, así que la que el emisor
 * anuncia en `identify` y la que el destinatario escribe en `to_publickey` tienen
 * que salir byte a byte iguales. Por eso se construyen aquí y no con lo que
 * devuelva `exportKey`, que añade campos y no promete el orden.
 */
function jwkString (x, y) {
  return JSON.stringify({ kty: 'EC', crv: 'P-256', x, y });
}

/**
 * Lo que va en el QR: versión + las dos llaves, como coordenadas sueltas.
 *
 * Se mandan solo `x` e `y` porque el resto del JWK es constante y el QR se paga por
 * byte: así el código de emparejamiento ocupa 177 caracteres en vez de casi 300.
 */
function encodePairing ({ publickey, encPub }) {
  const sign = JSON.parse(publickey);
  const enc = JSON.parse(encPub);
  return [PAIRING_VERSION, sign.x, sign.y, enc.x, enc.y].join('.');
}

/** Lee el código de emparejamiento. Devuelve `null` si no es uno válido. */
function decodePairing (raw) {
  const parts = String(raw || '').replace(/^#/, '').split('.');
  if (parts.length !== 5 || parts[0] !== PAIRING_VERSION) return null;
  const [, signX, signY, encX, encY] = parts;
  if (![signX, signY, encX, encY].every((coord) => COORD.test(coord))) return null;
  return { publickey: jwkString(signX, signY), encPub: jwkString(encX, encY) };
}

class QRShareApp {
  constructor () {
    this.client = null;
    this.publickey = null;      // mi llave de firma (por dónde me escriben)
    this.encPub = null;         // mi llave de cifrado (con qué me sellan)
    this.encPrivateKey = null;
    this.peer = null;           // { publickey, encPub } del otro lado
    this.role = null;
    this.pc = null;
    this.dc = null;
    this.files = new Map();
    this.receivedChunks = [];
    this.receivedBytes = 0;
    this._identified = null;

    // Asa para las pruebas de punta a punta (§5: las apps se prueban con Playwright).
    window.qrshareApp = this;

    this.init();
  }

  async init () {
    this.detectRole();
    this.renderUI();
    if (this.role === 'stale') return;
    try {
      await this.connect();
    } catch (error) {
      this.reportFailure('No se pudo conectar', error);
    }
  }

  detectRole () {
    const pairing = decodePairing(window.location.hash);
    if (pairing) {
      this.peer = pairing;
      this.role = 'receiver';
      return;
    }
    // Un enlace que trae algo pero no es un emparejamiento válido NO se trata como
    // «soy el emisor»: eso sería atender en silencio a quien pedía otra cosa. Los
    // enlaces `?peer=<token>` de la versión anterior caen justo aquí.
    const hasStaleLink = window.location.hash.length > 1 ||
      new URLSearchParams(window.location.search).has('peer');
    this.role = hasStaleLink ? 'stale' : 'sender';
  }

  // ===== TRANSPORTE =====

  async connect () {
    const own = await makeEncKeypair();
    this.encPrivateKey = own.privateKey;
    this.encPub = own.encPub;

    const exported = JSON.parse(await getPublicKeyJwk());
    this.publickey = jwkString(exported.x, exported.y);

    this.client = new WebSocketProxyClient({
      url: PROXY_URL,
      // Nada en claro, ni al enviar ni al recibir. Las dos direcciones, porque la
      // que falta es la que se salta el sellado entero (§4.1).
      requireSealed: true,
      myEncPrivateKey: this.encPrivateKey,
      // El canal de datos del archivo lo negocia esta app con su propio
      // RTCPeerConnection; el WebRTC del pilar solo sirve al envío por token, que
      // aquí no se usa. Encenderlo sería negociar dos veces para nada.
      enableWebRTC: false,
    });

    this.client.on('message', (from, payload, meta) => {
      this.onSignal(payload, meta, from);
    });
    this.client.on('error', (error) => this.onTransportError(error));
    // Una reconexión trae un token nuevo, y el proxio pierde a quién pertenecía el
    // anterior: hay que volver a identificarse o nadie puede escribirnos.
    this.client.on('token', () => {
      this._identified = this.identifySelf();
      this._identified.catch((error) => this.reportFailure('No se pudo identificar', error));
    });

    await this.client.connect();
    await this._identified;

    if (this.role === 'sender') this.onSenderReady();
    else this.onReceiverReady();
  }

  identifySelf () {
    return this.client.identifyAs({ publickey: this.publickey, sign: signData });
  }

  /**
   * El enlace que se pinta en el QR: mis dos llaves, en el `#fragment`.
   *
   * Va en el fragmento y no en la query porque el fragmento NO llega al servidor
   * (CLAUDE.md, §SEO): lo que empareja a dos aparatos no tiene por qué pasar por
   * los registros de nadie.
   */
  pairingUrl () {
    if (!this.publickey || !this.encPub) {
      throw errorWithCode('pairing url requested before the transport was ready', 'not-ready');
    }
    const code = encodePairing({ publickey: this.publickey, encPub: this.encPub });
    return `${window.location.origin}${window.location.pathname}#${code}`;
  }

  /**
   * Mandar señalización al otro lado, SELLADA.
   *
   * Sin la llave de cifrado del destinatario no hay sobre que valga, y entonces esto
   * se para con `code: 'unsealed'` — no manda en claro «para que al menos funcione».
   * El code importa: «no tengo la llave del otro lado» se arregla emparejando y «se
   * cayó la red» esperando, y confundirlos cuesta la tarde (§4.1).
   */
  async sendSignal (payload) {
    if (!this.peer || !this.peer.publickey || !this.peer.encPub) {
      throw errorWithCode('sendSignal: no paired peer keys', 'unsealed');
    }
    // `ephemeral`: la señalización caduca. Entregar una oferta SDP mañana no es
    // tarde, es incorrecto — reinicia una negociación imposible.
    await this.client.sendSealed([this.peer.publickey], payload, {
      peerEncPub: this.peer.encPub,
      ephemeral: true,
    });
  }

  /**
   * Lo que llega. El sobre lo abre el PILAR, no la app: si abrieran los dos, el
   * primero que llega sin la llave lo descarta y el otro no ve nada nunca. Aquí solo
   * se comprueba que venía sellado.
   */
  onSignal (payload, meta, from) {
    if (!meta || meta.sealed !== true) {
      this.reportFailure('Se descartó un mensaje sin sellar', errorWithCode(
        `rejected an unsealed message from ${from}`, 'unsealed'));
      return;
    }
    if (this.role === 'sender') this.handleSenderMessage(payload);
    else this.handleReceiverMessage(payload);
  }

  onTransportError (error) {
    const code = error && error.type;
    if (code === 'unsealed') {
      this.reportFailure('Se descartó un mensaje sin sellar', errorWithCode(
        `transport dropped a plaintext message (${error.reason})`, 'unsealed'));
      return;
    }
    if (code === 'undecipherable') {
      this.reportFailure('Llegó un mensaje que no es para este dispositivo', errorWithCode(
        'sealed for somebody else, or tampered with', 'undecipherable'));
      return;
    }
    console.error('[qrshare] transport error:', error);
  }

  /** Un fallo se ve y se dice: nada de seguir como si nada. */
  reportFailure (text, error) {
    const code = error && error.code ? ` [${error.code}]` : '';
    console.error('[qrshare] %s%s: %s', text, code, (error && error.message) || error);
    this.updateStatus(text + code, true);
    const banner = document.getElementById('appError');
    if (banner) {
      banner.textContent = text + code;
      banner.style.display = 'block';
    }
  }

  // ===== EMISOR =====

  onSenderReady () {
    // No se vuelve a renderizar: `renderUI()` ya pintó la pantalla antes de
    // conectar, y repintar aquí borraría un archivo elegido mientras tanto.
    console.log('[qrshare] sender ready');
  }

  renderSenderUI () {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="sender-container">
        <h1>QRShare</h1>
        <p class="subtitle">Comparte archivos P2P con WebRTC</p>

        <div id="appError" class="error" style="display: none;"></div>

        <button id="selectBtn" class="btn btn-primary" data-testid="select-file">Seleccionar Archivo</button>
        <input type="file" id="fileInput" />

        <table class="files-table" style="display: none;">
          <thead>
            <tr>
              <th>Archivo</th>
              <th>Tamaño</th>
              <th>Estado</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody id="filesTableBody">
          </tbody>
        </table>

        <div class="empty-state" id="emptyState">
          <p>No hay archivos seleccionados</p>
          <p>Haz clic en "Seleccionar Archivo" para comenzar</p>
        </div>
      </div>

      <div id="qrModal" class="modal">
        <div class="modal-content">
          <button class="modal-close" id="closeModal">&times;</button>
          <h2>Compartir Archivo</h2>
          <div id="qrContainer" data-testid="qr"></div>
          <div class="file-info-modal">
            <p><strong>Archivo:</strong> <span id="modalFileName"></span></p>
            <p><strong>URL:</strong> <span id="modalFileUrl" data-testid="pairing-url"></span></p>
          </div>
          <div id="transferProgress">
            <p style="font-weight: 600; margin-bottom: 12px;">Progreso de transferencia:</p>
            <div id="progressBar"><div id="progressFill"></div></div>
            <div id="progressText"></div>
          </div>
          <button id="copyUrlBtn" class="btn btn-secondary" style="width: 100%; margin-top: 16px;">Copiar URL</button>
        </div>
      </div>
    `;

    document.getElementById('selectBtn').addEventListener('click', () => this.selectFile());
    document.getElementById('fileInput').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        this.addFile(file);
      }
    });
    document.getElementById('closeModal').addEventListener('click', () => this.closeModal());
    document.getElementById('copyUrlBtn').addEventListener('click', () => this.copyUrl());

    document.getElementById('qrModal').addEventListener('click', (e) => {
      if (e.target.id === 'qrModal') this.closeModal();
    });
  }

  selectFile () {
    document.getElementById('fileInput').click();
  }

  addFile (file) {
    const fileId = 'file_' + Date.now();
    this.files.set(fileId, {
      id: fileId,
      file: file,
      name: file.name,
      size: file.size,
      type: file.type,
      shared: false,
      progress: 0,
      status: 'pending'
    });

    this.updateFilesTable();
  }

  updateFilesTable () {
    const table = document.querySelector('.files-table');
    const tbody = document.getElementById('filesTableBody');
    const emptyState = document.getElementById('emptyState');

    if (this.files.size === 0) {
      table.style.display = 'none';
      emptyState.style.display = 'block';
      return;
    }

    table.style.display = 'table';
    emptyState.style.display = 'none';
    tbody.innerHTML = '';

    this.files.forEach((fileInfo, fileId) => {
      const row = document.createElement('tr');
      let actionBtn = '';

      if (!fileInfo.shared) {
        actionBtn = `<button class="btn btn-primary share-btn" data-testid="share" data-file-id="${fileId}" style="padding: 6px 12px; font-size: 0.9em;">Compartir</button>`;
      } else {
        actionBtn = `<button class="btn btn-secondary show-qr-btn" data-testid="show-qr" data-file-id="${fileId}" style="padding: 6px 12px; font-size: 0.9em;">Ver QR</button>`;
      }

      row.innerHTML = `
        <td class="file-name">${fileInfo.name}</td>
        <td class="file-size">${this.formatSize(fileInfo.size)}</td>
        <td><span class="file-status status-${fileInfo.status}" data-testid="file-status">${this.getStatusText(fileInfo.status, fileInfo.progress)}</span></td>
        <td>${actionBtn}</td>
      `;

      if (!fileInfo.shared) {
        row.querySelector('.share-btn').addEventListener('click', () => this.shareFile(fileId));
      } else {
        row.querySelector('.show-qr-btn').addEventListener('click', () => this.showQR(fileId));
      }

      tbody.appendChild(row);
    });
  }

  getStatusText (status, progress) {
    if (status === 'pending') return 'Pendiente';
    if (status === 'transferring') return `Transfiriendo ${progress}%`;
    if (status === 'sent') return 'Enviado';
    if (status === 'completed') return 'Completado';
    return 'Compartido';
  }

  shareFile (fileId) {
    const fileInfo = this.files.get(fileId);
    fileInfo.shared = true;
    fileInfo.status = 'shared';
    this.files.set(fileId, fileInfo);
    this.updateFilesTable();
    this.showQR(fileId);
  }

  showQR (fileId) {
    const fileInfo = this.files.get(fileId);
    let url;
    try {
      url = this.pairingUrl();
    } catch (error) {
      this.reportFailure('Todavía no hay conexión con el proxio', error);
      return;
    }

    document.getElementById('modalFileName').textContent = fileInfo.name;
    document.getElementById('modalFileUrl').textContent = url;

    const qrContainer = document.getElementById('qrContainer');
    qrContainer.innerHTML = '';

    try {
      const qrCode = new QRCodeStyling({
        width: 240,
        height: 240,
        type: 'svg',
        data: url,
        dotsOptions: {
          color: '#000000',
          type: 'square'
        },
        backgroundOptions: {
          color: '#ffffff'
        }
      });
      qrCode.append(qrContainer);
    } catch (error) {
      console.error('[qrshare] could not render the QR:', error);
      qrContainer.innerHTML = `<div style="padding: 20px; border: 1px solid #ccc; background: #f9f9f9; border-radius: 8px;"><p><strong>URL:</strong></p><p style="word-break: break-all; font-family: monospace; font-size: 0.9em;">${url}</p></div>`;
    }

    document.getElementById('qrModal').classList.add('show');
    this.currentFileId = fileId;
  }

  closeModal () {
    document.getElementById('qrModal').classList.remove('show');
  }

  copyUrl () {
    const url = document.getElementById('modalFileUrl').textContent;
    navigator.clipboard.writeText(url).catch((error) => {
      this.reportFailure('No se pudo copiar la URL', error);
    });
  }

  handleSenderMessage (msg) {
    if (msg.type === 'hello') {
      // El QR va en una sola dirección: aquí es donde el emisor se entera de con
      // qué llave sellar la respuesta. Sin las dos, no hay conversación.
      if (typeof msg.publickey !== 'string' || typeof msg.encPub !== 'string') {
        this.reportFailure('El otro dispositivo no envió sus llaves', errorWithCode(
          'hello without pairing keys', 'unsealed'));
        return;
      }
      this.peer = { publickey: msg.publickey, encPub: msg.encPub };
      console.log('[qrshare] receiver paired');
      this.createOffer(this.currentFileId).catch((error) => {
        this.reportFailure('No se pudo enviar la oferta', error);
      });
    }
    else if (msg.type === 'answer') {
      console.log('[qrshare] answer received');
      if (this.pc) {
        this.pc.setRemoteDescription(new RTCSessionDescription(msg.sdp))
          .catch((error) => this.reportFailure('Respuesta inválida', error));
      }
    }
    else if (msg.type === 'ice') {
      if (this.pc && msg.candidate) {
        this.pc.addIceCandidate(new RTCIceCandidate(msg.candidate))
          .catch(e => console.warn('[qrshare] ICE error:', e));
      }
    }
  }

  async createOffer (fileId) {
    this.pc = new RTCPeerConnection({ iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' }
    ] });
    this.dc = this.pc.createDataChannel('fileTransfer', { ordered: true });

    this.dc.onopen = () => {
      console.log('[qrshare] data channel open');
      this.startSendingFile(fileId);
    };

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.sendSignal({ type: 'ice', candidate: e.candidate })
          .catch((error) => this.reportFailure('No se pudo enviar un candidato', error));
      }
    };

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    await this.sendSignal({ type: 'offer', sdp: this.pc.localDescription });
  }

  startSendingFile (fileId) {
    const fileInfo = this.files.get(fileId);
    const file = fileInfo.file;
    const CHUNK_SIZE = 64 * 1024;

    // Metadatos del archivo
    this.dc.send(JSON.stringify({
      type: 'metadata',
      name: file.name,
      size: file.size,
      mimeType: file.type
    }));

    let offset = 0;

    const sendNextChunk = () => {
      if (offset >= file.size) {
        this.dc.send(JSON.stringify({ type: 'end' }));
        fileInfo.status = 'sent';
        this.files.set(fileId, fileInfo);
        this.updateFilesTable();
        return;
      }

      // Backpressure
      if (this.dc.bufferedAmount > CHUNK_SIZE * 8) {
        this.dc.onbufferedamountlow = () => {
          this.dc.onbufferedamountlow = null;
          sendNextChunk();
        };
        return;
      }

      const chunk = file.slice(offset, offset + CHUNK_SIZE);
      const reader = new FileReader();

      reader.onload = (e) => {
        this.dc.send(e.target.result);
        offset += chunk.size;

        const progress = Math.round((offset / file.size) * 100);
        fileInfo.progress = progress;
        fileInfo.status = 'transferring';
        this.files.set(fileId, fileInfo);
        this.updateFilesTable();

        document.getElementById('transferProgress').style.display = 'block';
        document.getElementById('progressFill').style.width = progress + '%';
        document.getElementById('progressText').textContent = `${this.formatSize(offset)} / ${this.formatSize(file.size)} (${progress}%)`;

        setTimeout(sendNextChunk, 0);
      };

      reader.readAsArrayBuffer(chunk);
    };

    fileInfo.status = 'transferring';
    this.files.set(fileId, fileInfo);
    this.updateFilesTable();
    sendNextChunk();
  }

  // ===== RECEPTOR =====

  onReceiverReady () {
    console.log('[qrshare] receiver ready');
    this.notifySender().catch((error) => {
      this.reportFailure('No se pudo avisar al emisor', error);
    });
  }

  renderReceiverUI () {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="receiver-container">
        <h1>QRShare</h1>
        <p class="subtitle">Recepción de archivo</p>

        <div id="appError" class="error" style="display: none;"></div>

        <div id="fileInfoReceiver">
          <div class="receiver-file-name" id="receiverFileName" data-testid="received-name"></div>
          <div class="receiver-file-detail" id="receiverFileSize"></div>
        </div>

        <div id="receiverStatus" data-testid="receiver-status">Conectando...</div>

        <div id="progressContainerReceiver">
          <div id="progressBar"><div id="progressFill"></div></div>
          <div id="progressText"></div>
        </div>

        <button id="downloadBtn" class="btn btn-primary" data-testid="download">Descargar Archivo</button>
      </div>
    `;
  }

  /** Un enlace de una versión anterior, o roto: se dice, no se atiende a medias. */
  renderStaleLinkUI () {
    const app = document.getElementById('app');
    app.innerHTML = `
      <div class="receiver-container">
        <h1>QRShare</h1>
        <div class="error" data-testid="stale-link">
          Este enlace no sirve para recibir un archivo: es de una versión anterior de
          la app o está incompleto. Pide al otro dispositivo que muestre el QR de nuevo.
        </div>
        <p><a href="./">Empezar de nuevo</a></p>
      </div>
    `;
  }

  /**
   * El primer mensaje del receptor, y el que cierra el círculo: va sellado con la
   * llave que venía en el QR, y lleva dentro las suyas para que el emisor pueda
   * contestar sellando también.
   */
  async notifySender () {
    await this.sendSignal({
      type: 'hello',
      publickey: this.publickey,
      encPub: this.encPub,
    });
    this.updateStatus('Esperando archivo...');
  }

  updateStatus (text, isError = false) {
    const statusEl = document.getElementById('receiverStatus');
    if (statusEl) {
      statusEl.textContent = text;
      statusEl.className = isError ? 'error' : '';
    }
  }

  handleReceiverMessage (msg) {
    if (msg.type === 'offer') {
      console.log('[qrshare] offer received');
      this.createAnswer(msg.sdp).catch((error) => {
        this.reportFailure('No se pudo responder a la oferta', error);
      });
    }
    else if (msg.type === 'ice') {
      if (this.pc && msg.candidate) {
        this.pc.addIceCandidate(new RTCIceCandidate(msg.candidate))
          .catch(e => console.warn('[qrshare] ICE error:', e));
      }
    }
  }

  async createAnswer (offer) {
    this.pc = new RTCPeerConnection({ iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' }
    ] });

    this.pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.sendSignal({ type: 'ice', candidate: e.candidate })
          .catch((error) => this.reportFailure('No se pudo enviar un candidato', error));
      }
    };

    this.pc.ondatachannel = (e) => {
      this.dc = e.channel;
      this.setupReceiverDataChannel();
    };

    await this.pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    await this.sendSignal({ type: 'answer', sdp: this.pc.localDescription });
  }

  setupReceiverDataChannel () {
    this.dc.onmessage = (e) => {
      if (typeof e.data === 'string') {
        const msg = JSON.parse(e.data);
        if (msg.type === 'metadata') {
          this.incomingSize = msg.size;
          document.getElementById('fileInfoReceiver').style.display = 'block';
          document.getElementById('receiverFileName').textContent = msg.name;
          document.getElementById('receiverFileSize').textContent = this.formatSize(msg.size);
          document.getElementById('progressContainerReceiver').style.display = 'block';
          this.updateStatus('Recibiendo...');
        }
        else if (msg.type === 'end') {
          this.completeTransfer();
        }
      } else {
        // Trozo binario
        this.receivedChunks.push(e.data);
        this.receivedBytes += e.data.byteLength;

        const fileSize = this.incomingSize || 0;
        if (fileSize > 0) {
          const progress = Math.round((this.receivedBytes / fileSize) * 100);
          document.getElementById('progressFill').style.width = progress + '%';
          document.getElementById('progressText').textContent =
            `${this.formatSize(this.receivedBytes)} / ${this.formatSize(fileSize)} (${progress}%)`;
        }
      }
    };

    this.dc.onerror = (e) => {
      console.error('[qrshare] data channel error:', e);
      this.updateStatus('Error en la transferencia', true);
    };
  }

  completeTransfer () {
    const fileName = document.getElementById('receiverFileName').textContent;
    const blob = new Blob(this.receivedChunks);
    const url = URL.createObjectURL(blob);

    const downloadBtn = document.getElementById('downloadBtn');
    downloadBtn.style.display = 'inline-block';
    downloadBtn.onclick = () => {
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
    };

    this.updateStatus('✓ Transferencia completada');
    document.getElementById('progressFill').style.width = '100%';
    downloadBtn.click();
  }

  // ===== UTILS =====

  formatSize (bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  renderUI () {
    if (this.role === 'sender') this.renderSenderUI();
    else if (this.role === 'stale') this.renderStaleLinkUI();
    else this.renderReceiverUI();
  }
}

// `type="module"` ya difiere el script hasta que el DOM está armado, pero el evento
// puede haberse disparado ya si algo tardó: se comprueba en vez de suponerlo.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => { new QRShareApp(); });
} else {
  new QRShareApp();
}
