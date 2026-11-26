// License Apache License 2.0


export function newIdempotencyKey(
  random: Pick<Crypto, 'getRandomValues'> = globalThis.crypto,
): string {
  return Array.from(random.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
}

export function publicPem(base64: string, label: string): string {
  const body =
    base64
      .replace(/\s/g, '')
      .match(/.{1,64}/g)
      ?.join('\n') || ''
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`
}

export function enrollmentActions(status: string, purpose: string): string[] {
  switch (status) {
    case 'PREPARED':
      return ['issue', 'cancel']
    case 'AWAITING_CERTIFICATE':
      return ['certificate', 'cancel']
    case 'CERTIFICATE_READY':
      return purpose === 'REGISTER_CA' ? ['register'] : []
    case 'FAILED':
      return purpose === 'REGISTER_CA' ? ['register'] : []
    case 'RESULT_UNKNOWN':
      return ['reconcile', 'certificate']
    case 'ISSUING':
    case 'REGISTERING':
      return ['reconcile']
    default:
      return []
  }
}
