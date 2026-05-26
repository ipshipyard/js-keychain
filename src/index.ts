/**
 * @packageDocumentation
 *
 * A WebCrypto-first keychain implementation for use with Helia and libp2p.
 *
 * ## Configuring additional implementations
 *
 * RSA and Ed25519 keys are supported out of the box but other schemes are
 * configurable by passing a `CryptoImplementationLoader` that can return
 * `CryptoKeyImplementation` instances.
 */
import { Keychain as KeychainClass } from './keychain.ts'
import type { AbortOptions } from 'abort-error'
import type { ComponentLogger } from 'birnam'
import type { Datastore } from 'interface-datastore'
import type { CID, MultihashDigest } from 'multiformats/cid'

export interface CryptoImplementationLoader {
  (codeOrName: number | string, options?: AbortOptions): CryptoImplementation | Promise<CryptoImplementation>
}

export interface PublicKey {
  /**
   * The type of the crypto implementation, e.g. `Ed15519`
   */
  readonly type: string

  /**
   * The code that is used as the `Type` field in the protobuf representation of
   * the public/private keys
   */
  readonly code: number

  /**
   * Return a MultihashDigest that represents this key
   */
  toMultihash (): MultihashDigest

  /**
   * Return the libp2p-key CID that represents this key
   */
  toCID (): CID<unknown, 0x72, number, 1>

  /**
   * Return this key encoded as a protobuf PublicKey message
   */
  toProtobuf (): Uint8Array<ArrayBuffer>

  /**
   * Verify the passed message against it's signature
   */
  verify(message: Uint8Array, signature: Uint8Array, options?: AbortOptions): boolean | Promise<boolean>
}

export function isPublicKey (obj?: any): obj is PublicKey {
  if (obj == null) {
    return false
  }

  return typeof obj.type === 'string' && typeof obj.code === 'number' && typeof obj.verify === 'function'
}

export interface PrivateKey {
  /**
   * The type of the crypto implementation, e.g. `Ed15519`
   */
  readonly type: string

  /**
   * The code that is used as the `Type` field in the protobuf representation of
   * the public/private keys
   */
  readonly code: number

  /**
   * The public key that corresponds to this private key
   */
  readonly publicKey: PublicKey

  /**
   * Return this key encoded as a protobuf PrivateKey message
   */
  toProtobuf (): Uint8Array<ArrayBuffer>

  /**
   * Sign the passed message and return a signature
   */
  sign(message: Uint8Array, options?: AbortOptions): Uint8Array<ArrayBuffer> | Promise<Uint8Array<ArrayBuffer>>
}

export function isPrivateKey (obj?: any): obj is PrivateKey {
  if (obj == null) {
    return false
  }

  return typeof obj.type === 'string' && typeof obj.code === 'number' && typeof obj.sign === 'function' && isPublicKey(obj.publicKey)
}

export interface CipherOptions extends AbortOptions {
  iterations?: number
  hash?: string
  keyLength?: number
  algorithm?: string
}

export interface EncryptionResult {
  salt: Uint8Array<ArrayBuffer>
  iv: Uint8Array<ArrayBuffer>
  cipherText: Uint8Array<ArrayBuffer>
}

export interface Cipher {
  encrypt(data: Uint8Array, options?: AbortOptions): Promise<EncryptionResult>
  decrypt(salt: Uint8Array, iv: Uint8Array, cipherText: Uint8Array, options?: CipherOptions): Promise<Uint8Array<ArrayBuffer>>
}

export interface CryptoImplementation {
  /**
   * The type of the crypto implementation, e.g. `Ed15519`
   */
  type: string

  /**
   * The code that is used as the `Type` field in the protobuf representation of
   * the public/private keys
   */
  code: number

  /**
   * Create a new private key
   */
  generatePrivateKey(options?: AbortOptions & Record<string, any>): Promise<PrivateKey>

  /**
   * Convert the passed bytes into a public key. The bytes come from the `.Data`
   * field of a `PublicKey` protobuf message.
   */
  publicKeyFromProtobuf(buf: Uint8Array, options?: AbortOptions): PublicKey | Promise<PublicKey>

  /**
   * Convert a private key into a string suitable for storing in a datastore
   */
  serialize (key: PrivateKey, cipher: Cipher, options?: AbortOptions): Promise<string>

  /**
   * Convert a string from a datastore into a private key
   */
  deserialize (pem: string, cipher: Cipher, options?: AbortOptions): Promise<PrivateKey>
}

export interface KeyInfo {
  /**
   * The hash of the key
   */
  id: string

  /**
   * The key name
   */
  name: string

  /**
   * The key type
   */
  type?: 'Ed25519' | 'RSA' | string
}

export interface GenerateKeyOptions extends AbortOptions, Record<string, any> {
  /**
   * The type of key to generate
   *
   * @default 'Ed25519'
   */
  type?: 'Ed25519' | 'RSA' | string
}

export interface Keychain {
  /**
   * Create a key of the passed type and store it under the specified name. A
   * cryptography implementation must be configured for the key type (defaults
   * to Ed25519).
   */
  generateKey (name: string, options?: AbortOptions & Record<string, any>): Promise<PrivateKey>

  /**
   * Import a new private key.
   *
   * The `type` parameter must match a supported cryptography implementation.
   *
   * The default supported key types are `Ed25519` and `RSA`, others may be
   * added through configuration.
   *
   * @example
   *
   * ```TypeScript
   * const key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
   * const raw = await crypto.subtle.exportKey('raw', key)
   * await helia.keychain.importKey('my-key', 'Ed25519', raw)
   * ```
   */
  importKey(name: string, key: PrivateKey, options?: AbortOptions): Promise<PrivateKey>

  /**
   * Export an existing private key.
   *
   * @example
   *
   * ```TypeScript
   * const raw = await helia.exportKey('my-key')
   * const key = await crypto.subtle.importKey('raw', raw, {
   *   name: 'Ed25519'
   * }, true, ['sign', 'verify'])
   * ```
   */
  exportKey(name: string, options?: AbortOptions): Promise<PrivateKey>

  /**
   * Removes a key from the keychain.
   *
   * @example
   *
   * ```TypeScript
   * await helia.keychain.removeKey('keyTest')
   * ```
   */
  removeKey(name: string, options?: AbortOptions): Promise<void>

  /**
   * Rename a key in the keychain. This is done in a batch commit with rollback
   * so errors thrown during the operation will not cause key loss.
   *
   * @example
   *
   * ```TypeScript
   * await helia.keychain.renameKey('oldName', 'newName')
   * ```
   */
  renameKey(oldName: string, newName: string, options?: AbortOptions): Promise<void>

  /**
   * List all the keys.
   *
   * @example
   *
   * ```TypeScript
   * for await (const name of helia.keychain.listKeys()) {
   *   // ...
   * }
   * ```
   */
  listKeys(options?: AbortOptions): AsyncGenerator<KeyInfo>

  /**
   * Re-encrypt all keys in the keychain using a crypto graphic key derived
   * from the password
   *
   * @example
   *
   * ```TypeScript
   * await helia.keychain.rotateKeychainPass('newPassword')
   * ```
   */
  rotateKeychainPass(password: string, options?: AbortOptions): Promise<void>

  /**
   * Attempts to load a public key from a serialized protobuf message conforming
   * to the `PublicKey` message.
   */
  loadPublicKeyFromProtobuf (buf: Uint8Array, options?: AbortOptions): Promise<PublicKey>
}

export interface KeychainInit {
  /**
   * The password is used to derive a key which encrypts the keychain at rest
   */
  password?: string

  /**
   * Specify a non-default PBK2 function salt
   */
  salt?: string

  /**
   * How many iterations to use when deriving a key from the password
   *
   * @default 10_000
   */
  iterations?: number

  /**
   * The hash type
   *
   * @default SHA2-512
   */
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512'

  /**
   * The 'self' key is the private key of the node from which the peer id is
   * derived.
   *
   * It cannot be renamed or removed.
   *
   * By default it is stored under the 'self' key, to use a different name, pass
   * this option.
   *
   * @default 'self'
   */
  selfKey?: string
}

export interface KeychainComponents {
  datastore: Datastore
  logger: ComponentLogger
  getCryptoImplementation: CryptoImplementationLoader
}

export function keychain (init?: KeychainInit): (components: KeychainComponents) => Keychain {
  return (components) => new KeychainClass(components, init)
}
