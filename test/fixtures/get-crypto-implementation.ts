import { ed25519Crypto, rsaCrypto } from '@ipshipyard/crypto'
import { UnknownCryptoImplementationError } from '../../src/errors.ts'
import type { CryptoImplementationLoader } from '../../src/index.ts'
import type { CryptoImplementation } from '@ipshipyard/crypto'

function isPromise <T = any> (obj?: any): obj is Promise<T> {
  return typeof obj?.then === 'function'
}

export function getCryptoImplementation (initialCryptos: Array<CryptoImplementation> = [], loadCrypto?: CryptoImplementationLoader): CryptoImplementationLoader {
  const cryptos: Record<string | number, CryptoImplementation> = {}

  initialCryptos = [
    ed25519Crypto(),
    rsaCrypto(),
    ...initialCryptos
  ]

  initialCryptos.forEach(crypto => {
    cryptos[crypto.type] = crypto
    cryptos[crypto.code] = crypto
  })

  return async (nameOrCode) => {
    let crypto = cryptos[nameOrCode]

    if (crypto == null && loadCrypto != null) {
      const res = loadCrypto(nameOrCode)

      if (isPromise(res)) {
        crypto = await res
      } else {
        crypto = res
      }

      cryptos[crypto.type] = crypto
      cryptos[crypto.code] = crypto
    }

    if (crypto != null) {
      return crypto
    }

    throw new UnknownCryptoImplementationError(`Could not load crypto for ${crypto}`)
  }
}
