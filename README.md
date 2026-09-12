# QRShare Web - P2P File Transfer con WebRTC

> **Parte del ecosistema [Dotrino](https://dotrino.com).** Dotrino es un ecosistema de aplicaciones centradas en la privacidad de los datos: tu información es tuya, y las decisiones sobre ella también — qué compartes, con quién, cuándo y por qué. Sin anuncios, sin cookies, sin rastreo de datos, sin vender tu identidad a nadie.

App web pura (HTML + CSS + JavaScript) para compartir archivos P2P con WebRTC. La señalización va por el transporte del ecosistema (`@dotrino/proxy-client`) y **sellada extremo a extremo**.

## Cómo usar

### 1. Servir la carpeta web

Cualquier servidor estático sirve. Por ejemplo:

```bash
npx http-server .
```

### 2. Acceder a la app

- **Sender (PC)**: `http://localhost:8080`
- **Receiver (móvil)**: Escanea el QR generado

## Arquitectura

### Flujo

1. El emisor conecta con `@dotrino/proxy-client` y se identifica ante el proxio con su
   llave de firma; además genera una llave de cifrado (`makeEncKeypair`).
2. Elige un archivo → el QR lleva la URL `#<versión>.<x>.<y>.<x>.<y>`: sus dos llaves
   públicas (firma + cifrado) en el `#fragment`, que **no llega al servidor**.
3. El receptor escanea → abre esa URL, conecta y se identifica.
4. Su primer mensaje (`hello`) va ya **sellado** con la llave del QR y lleva dentro
   las suyas: así el emisor puede sellar la respuesta. El QR va en una sola
   dirección; esto cierra la otra.
5. SDP/ICE se intercambian con `sendSealed()` por `wss://proxy.dotrino.com`. Los dos
   clientes arrancan con `requireSealed: true`, así que ninguno manda ni acepta nada
   en claro.
6. Abre el Data Channel de WebRTC → transferencia P2P en trozos de 64 KB.
7. Descarga automática al completar.

### Por qué va sellado

El proxio **enruta, pero no cifra**: `sendByPubkey` manda el payload tal cual
(CONVENCIONES §4.1). Una oferta SDP lleva las direcciones IP del aparato y dice con
quién se conecta, así que en claro la leería quien opera el proxio. El sellado es el
del pilar (`wrapForMember`/`openWrap` de `@dotrino/identity/content`), no uno propio.

### Componentes

| Archivo | Descripción |
|---------|-------------|
| `index.html` | HTML mínimo + scripts de CDN |
| `styles.css` | Estilos para emisor y receptor |
| `app.js` | Lógica completa (transporte sellado, WebRTC, UI) |

### Dependencias del ecosistema

Se cargan por jsDelivr, siempre con `+esm`:

- `@dotrino/proxy-client@0.19` — el transporte. **No** se escribe un cliente propio.
- `@dotrino/identity@0.89/content` — la cripto del sellado, inyectada con
  `setSealingPrimitives()`.
- `@dotrino/topbar` — la barra superior estándar.

## Características

- P2P directo — los archivos no pasan por el servidor
- Señalización sellada extremo a extremo
- Interfaz responsive (PC y móvil)
- QR generado dinámicamente
- Barra de progreso en tiempo real
- Descarga automática al completar
- Backpressure para no desbordar el canal

## Requisitos

- Navegador moderno con soporte WebRTC
- Acceso a `wss://proxy.dotrino.com`

## Troubleshooting

### "No se conecta al proxio"
- Verificar que `wss://proxy.dotrino.com` esté disponible
- Revisar consola del navegador (F12)

### "No aparece el QR"
- Verificar que el CDN de qr-code-styling esté disponible
- Fallback a texto de URL

### "Transferencia lenta"
- Es normal en redes 4G/5G
- El bottleneck es la conexión del móvil, no WebRTC

### "No descarga el archivo"
- Verificar que el navegador permite descargas automáticas
- Intentar descargar manualmente con el botón

## Notas técnicas

- **Chunking**: 64 KB por chunk
- **ICE Servers**: STUN público. El TURN del ecosistema todavía no está cableado aquí
- **Servidor de señalización**: Solo metadatos, no archivos

## Desarrollo

Para apuntar a otro proxio, edita la constante `PROXY_URL` de `app.js`.

Para cambiar el tamaño de trozo, en `startSendingFile()`:

```js
const CHUNK_SIZE = 128 * 1024; // 128 KB
```
