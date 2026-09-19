/**
 * Shared pieces of the cross-implementation interop harness: NoiseHFS setup,
 * a TCP socket adapter, port parsing, and the one-line greeting exchange
 * every implementation's harness speaks (listener sends first).
 */
import { defaultLogger } from '@libp2p/logger'
import { AbstractMultiaddrConnection } from '@libp2p/utils'
import { NoiseHFS } from '../dist/src/noise-hfs.js'

export const IMPL = 'JS'
export const GREETING_PREFIX = 'hello from '

export function createNoiseHFS (privateKey, peerId) {
  return new NoiseHFS({ privateKey, peerId, logger: defaultLogger(), upgrader: { getStreamMuxers: () => new Map() } })
}

export class TCPSocketConnection extends AbstractMultiaddrConnection {
  #socket

  constructor (init) {
    super(init)
    this.#socket = init.socket
    this.#socket.on('data', buf => this.onData(buf))
    this.#socket.on('error', err => this.abort(err))
    this.#socket.setTimeout(30_000)
    this.#socket.once('timeout', () => this.abort(new Error('TCP timeout')))
    this.#socket.once('end', () => this.onTransportClosed())
    this.#socket.once('close', hadError => {
      if (hadError) this.abort(new Error('TCP transmission error'))
      else this.onTransportClosed()
    })
    this.#socket.on('drain', () => this.safeDispatchEvent('drain'))
  }

  sendData (data) {
    let sentBytes = 0
    let canSendMore = true
    for (const buf of data) {
      sentBytes += buf.byteLength
      canSendMore = this.#socket.write(buf)
    }
    return { sentBytes, canSendMore }
  }

  async sendClose () {
    if (this.#socket.destroyed) return
    await new Promise(resolve => {
      this.#socket.once('close', resolve)
      this.#socket.destroySoon()
    })
  }

  sendReset () { this.#socket.resetAndDestroy() }
  sendPause () { this.#socket.pause() }
  sendResume () { this.#socket.resume() }
}

export function parsePort (argv, fallback) {
  const i = argv.indexOf('--port')
  if (i >= 0 && argv[i + 1] === undefined) throw new Error('--port requires a value')
  const raw = i >= 0 ? argv[i + 1] : argv.find(a => /^\d+$/.test(a))
  if (raw === undefined) return fallback
  if (!/^\d+$/.test(raw)) throw new Error(`invalid port ${raw}`)
  const port = Number.parseInt(raw, 10)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid port ${raw}`)
  return port
}

export async function sendGreeting (connection) {
  connection.send(new TextEncoder().encode(`${GREETING_PREFIX}${IMPL}\n`))
  console.log(`SENT ${GREETING_PREFIX}${IMPL}`)
}

// A greeting is "hello from <Impl>\n", under 32 bytes. The cap is generous
// enough that no legitimate peer can reach it, and small enough that a peer
// which completed the handshake and then floods newline-free data cannot grow
// the accumulator until the process is OOM-killed. Completing XXhfs proves the
// peer holds some libp2p identity, not that it is friendly.
export const MAX_GREETING_BYTES = 1024

// The greeting is peer-controlled and the RECV line lands in a committed run
// log that humans later read with `cat`. Escape control characters so ANSI CSI
// and OSC sequences cannot rewrite a reviewer's terminal. A legitimate
// "hello from <Impl>" contains none of these, so the runner's grep contract
// (an exact match on `RECV hello from <Impl>`) is unchanged.
export function printableGreeting (line) {
  return line.replace(/\p{C}/gu, ch => `\\x${ch.codePointAt(0).toString(16).padStart(2, '0')}`)
}

export async function readGreeting (connection) {
  const decoder = new TextDecoder()
  let text = ''
  for await (const chunk of connection) {
    text += decoder.decode(chunk instanceof Uint8Array ? chunk : chunk.subarray(), { stream: true })
    const nl = text.indexOf('\n')
    if (nl >= 0) {
      const line = text.slice(0, nl)
      console.log(`RECV ${printableGreeting(line)}`)
      if (!line.startsWith(GREETING_PREFIX) || line.length === GREETING_PREFIX.length) {
        throw new Error(`unexpected greeting ${JSON.stringify(line)}`)
      }
      return line
    }
    if (text.length > MAX_GREETING_BYTES) {
      throw new Error(`greeting exceeded ${MAX_GREETING_BYTES} bytes without a newline`)
    }
  }
  throw new Error('connection closed before a greeting arrived')
}

// process.exit() straight after a write can drop output still buffered for a
// pipe, so exit only from the callback of a final empty write to each stream.
export function exitAfterFlush (code) {
  process.exitCode = code
  process.stdout.write('', () => process.stderr.write('', () => process.exit(code)))
}

export function fail (err) {
  process.stderr.write(`ERROR ${err?.message ?? err}\n`)
  exitAfterFlush(1)
}
