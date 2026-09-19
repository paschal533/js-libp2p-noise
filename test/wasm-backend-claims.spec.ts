/**
 * Guards against claiming a WebAssembly KEM backend that does not exist.
 *
 * `src/crypto/pqc.wasm.ts` is a stub that re-exports the pure-JS noble path.
 * Its header used to tell readers to edit `src-wasm/src/lib.rs` and run
 * `pnpm run build:wasm`; neither has ever existed in this repository. Worse,
 * `benchmarks/benchmark-pqc.js` wrapped the stub import in a try/catch that
 * expected it to fail, so the import succeeded and the harness printed rows
 * labelled `[WASM]` that were measurements of the identical pure-JS object.
 *
 * These checks are deliberately source-level: the failure mode is a published
 * number carrying a label its code cannot support, and only the label is
 * observable (security audit 2026-09-18, supply-chain SC-013).
 */
import { readFileSync } from 'fs'
import { dirname, resolve } from 'path'
import { fileURLToPath } from 'url'
import { expect } from 'aegir/chai'
import { pqcKem } from '../src/crypto/pqc.js'
import { pqcKemWasm } from '../src/crypto/pqc.wasm.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(__dirname, '../..')
const read = (rel: string): string => readFileSync(resolve(repoRoot, rel), 'utf-8')

const SOURCES = ['src/crypto/pqc.wasm.ts', 'benchmarks/benchmark-pqc.js']

describe('WASM backend claims', () => {
  it('the stub is the pure-JS KEM, not a second backend', () => {
    // If this ever stops holding, a real WASM backend has landed and the
    // benchmark may legitimately report a separate WASM row again.
    expect(pqcKemWasm).to.equal(pqcKem)
  })

  it('does not point readers at a src-wasm directory that does not exist', () => {
    for (const rel of SOURCES) {
      expect(read(rel), rel).to.not.match(/src-wasm/)
    }
  })

  it('mentions build:wasm only if package.json actually defines it', () => {
    const scripts = JSON.parse(read('package.json')).scripts ?? {}
    const defined = Object.hasOwn(scripts, 'build:wasm')
    for (const rel of SOURCES) {
      if (!defined) {
        expect(read(rel), `${rel} names a script package.json does not define`).to.not.match(/build:wasm/)
      }
    }
  })

  it('labels no benchmark output as WASM while the stub is pure JS', () => {
    const benchmark = read('benchmarks/benchmark-pqc.js')
    expect(benchmark).to.not.match(/\[WASM\]/)
    expect(benchmark).to.not.match(/WASM KEM/)
  })
})
