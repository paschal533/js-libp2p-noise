/**
 * Compatibility alias for the ML-KEM-768 KEM. There is no WebAssembly
 * backend: every export here is the pure-JS noble path from `pqc.ts`, and
 * `initWasmKem()` is a no-op.
 *
 * The WASM module this file is named after was compiled for X-Wing and was
 * never part of this repository. It was not ported when the implementation
 * moved to raw ML-KEM-768, so nothing in `src/` imports this file. An earlier
 * header sent readers to a Rust source directory and a pnpm build script,
 * neither of which has ever existed here, and callers that treated an import
 * failure as "no WASM build" were silently measuring pure JS instead.
 *
 * If a real WASM backend is reintroduced, commit its source and a build
 * script rather than a prebuilt binary, and only then reinstate a separate
 * WASM label anywhere that reports numbers.
 */

import { pureJsCrypto } from './js.js'
import { pqcKem } from './pqc.js'
import type { ICryptoInterface } from '../crypto.js'
import type { IKem } from '../kem.js'

export async function initWasmKem (): Promise<void> {
  // No-op: pure-JS backend needs no initialisation.
}

export const pqcKemWasm: IKem = pqcKem

export const pqcCryptoWasm: ICryptoInterface & IKem = {
  ...pureJsCrypto,
  ...pqcKem
}
