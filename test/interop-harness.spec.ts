/**
 * Bounds checks for the interop harness helpers in `scripts/interop-io.mjs`.
 *
 * The harness reads one `hello from <Impl>\n` greeting from a peer that has
 * completed the handshake but is not otherwise trusted. Completing XXhfs
 * proves the peer holds some libp2p identity, not that it is friendly, so the
 * greeting reader must refuse to buffer an unbounded amount of newline-free
 * data (security audit 2026-09-18, harnesses-tooling F-001).
 *
 * The harness lives outside `src/`, so it is loaded by URL at runtime rather
 * than by a build-time relative import.
 */
import { expect } from 'aegir/chai'

interface InteropIo {
  MAX_GREETING_BYTES: number
  printableGreeting(line: string): string
  readGreeting(connection: AsyncIterable<Uint8Array>): Promise<string>
}

/** Yields `total` bytes of `fill` in `chunk`-sized pieces, with no newline. */
async function * newlineFreeStream (total: number, chunk = 64, fill = 0x41): AsyncGenerator<Uint8Array> {
  let sent = 0
  while (sent < total) {
    const size = Math.min(chunk, total - sent)
    yield new Uint8Array(size).fill(fill)
    sent += size
  }
}

async function * once (text: string): AsyncGenerator<Uint8Array> {
  yield new TextEncoder().encode(text)
}

describe('interop harness greeting reader', () => {
  let io: InteropIo

  before(async () => {
    io = await import(new URL('../../scripts/interop-io.mjs', import.meta.url).href)
  })

  it('exposes a greeting cap comfortably above the longest real greeting', () => {
    expect(io.MAX_GREETING_BYTES).to.be.a('number')
    expect(io.MAX_GREETING_BYTES).to.be.greaterThan('hello from Python\n'.length)
    expect(io.MAX_GREETING_BYTES).to.be.at.most(4096)
  })

  it('reads a well-formed greeting unchanged', async () => {
    const line = await io.readGreeting(once('hello from Rust\ntrailing junk'))
    expect(line).to.equal('hello from Rust')
  })

  it('rejects a newline-free stream once it passes the cap', async () => {
    const stream = newlineFreeStream(io.MAX_GREETING_BYTES * 4)
    await expect(io.readGreeting(stream)).to.eventually.be.rejectedWith(/exceeded .* bytes without a newline/)
  })

  it('stops consuming the stream instead of draining it', async () => {
    // A hostile peer streams forever. The reader must give up at the cap
    // rather than buffering until the process dies.
    let produced = 0
    const endless = (async function * () {
      while (true) {
        produced += 256
        yield new Uint8Array(256).fill(0x41)
      }
    })()

    await expect(io.readGreeting(endless)).to.eventually.be.rejectedWith(/exceeded/)
    expect(produced).to.be.at.most(io.MAX_GREETING_BYTES + 512)
  })

  it('escapes control characters before echoing a greeting', () => {
    // A hostile peer can put ANSI CSI or OSC sequences in the greeting; the
    // RECV line is committed to a run log that humans read with `cat`.
    const hostile = 'hello from JS[2K[1APASS'
    const escaped = io.printableGreeting(hostile)
    expect(escaped).to.not.include('')
    expect(escaped).to.include('\\x1b')
  })

  it('leaves a legitimate greeting byte-identical, preserving the grep contract', () => {
    // run-matrix.sh grades on an exact match of `RECV hello from <Impl>`.
    for (const impl of ['JS', 'Rust', 'Python', 'Nim']) {
      expect(io.printableGreeting(`hello from ${impl}`)).to.equal(`hello from ${impl}`)
    }
  })

  it('still accepts a greeting that arrives in several chunks', async () => {
    const chunked = (async function * () {
      yield new TextEncoder().encode('hello ')
      yield new TextEncoder().encode('from ')
      yield new TextEncoder().encode('JS\n')
    })()
    expect(await io.readGreeting(chunked)).to.equal('hello from JS')
  })
})
