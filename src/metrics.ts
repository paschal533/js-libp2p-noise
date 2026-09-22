import type { Counter, Metrics } from '@libp2p/interface'

export type MetricsRegistry = Record<string, Counter>

export function registerMetrics (metrics: Metrics): MetricsRegistry {
  return {
    xxHandshakeSuccesses: metrics.registerCounter(
      'libp2p_noise_xxhandshake_successes_total', {
        help: 'Total count of noise xxHandshakes successes_'
      }),

    xxHandshakeErrors: metrics.registerCounter(
      'libp2p_noise_xxhandshake_error_total', {
        help: 'Total count of noise xxHandshakes errors'
      }),

    encryptedPackets: metrics.registerCounter(
      'libp2p_noise_encrypted_packets_total', {
        help: 'Total count of noise encrypted packets successfully'
      }),

    decryptedPackets: metrics.registerCounter(
      'libp2p_noise_decrypted_packets_total', {
        help: 'Total count of noise decrypted packets'
      }),

    decryptErrors: metrics.registerCounter(
      'libp2p_noise_decrypt_errors_total', {
        help: 'Total count of noise decrypt errors'
      }),

    // Counted separately from xxHandshakeErrors: a downgrade is an attack
    // signal, and burying it in the generic error counter would make the one
    // thing this mechanism exists to detect invisible in monitoring.
    downgradesDetected: metrics.registerCounter(
      'libp2p_noise_security_protocol_downgrades_total', {
        help: 'Total count of handshakes whose negotiated security protocol contradicted the peers\' signed offers'
      })
  }
}
