/** Disable some linting rules to allow use of untyped JS libs. */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-var-requires */

import secp256k1 from 'secp256k1'
import ASN1 from './asn1'

// Following libraries do not include .d.ts files.
/* eslint-disable @typescript-eslint/no-var-requires */
const base58Check = require('bs58check')
const blakejs = require('blakejs')
/* eslint-enable @typescript-eslint/no-var-requires */

/** Common utility functions */
const utils = {
  /**
   * Compress an EDCSA public key.
   * See: https://bitcointalk.org/index.php?topic=644919.0
   */
  compressKey(uncompressed: Uint8Array): Uint8Array {
    const uncompressedKeySize = 65

    if (uncompressed.length !== uncompressedKeySize) {
      throw new Error('Invalid length for uncompressed key')
    }
    const firstByte = uncompressed[0]
    if (firstByte !== 4) {
      throw new Error('Invalid compression byte')
    }

    // Assign a magic byte based on the parity of y coordinate.
    const lastByte = uncompressed[64]
    const magicByte = lastByte % 2 === 0 ? 2 : 3

    // X Coordinates are the first 32 bytes after the magic prefix byte.
    const xBytes = uncompressed.slice(1, 33)

    // Compressed key is 1 byte indicating parity of y and full x.
    return this.mergeBytes(new Uint8Array([magicByte]), xBytes)
  },

  /**
   * Calculate the blake2b hash of the the given bytes.
   *
   * @param input The bytes to hash.
   * @param length The length of the output.
   * @returns The resulting hash.
   */
  blake2b(input: Uint8Array, length: number): Uint8Array {
    return blakejs.blake2b(input, null, length)
  },

  /**
   * Normalize a signature to lower-s-form notation.
   *
   * @param signature The signature to normalize
   * @returns The normalized signature.
   */
  normalizeSignature(signature: Uint8Array): Uint8Array {
    return secp256k1.signatureNormalize(signature)
  },

  /**
   * Convert a DER encoded signature to the corresponding raw form.
   *
   * @param derSignature Bytes representing a DER encoded signature
   * @returns Bytes representing a raw signature.
   */
  derSignatureToRaw(derSignature: Uint8Array): Uint8Array {
    const decodedSignature = ASN1.decode(derSignature)
    const rHex: string = decodedSignature.sub[0].toHexStringContent()
    const sHex: string = decodedSignature.sub[1].toHexStringContent()
    return this.hexToBytes(rHex + sHex)
  },

  /**
   * Base58Check encode the given bytes with the given prefix.
   *
   * @param bytes The bytes to encode.
   * @param prefix A prefix to prepend to the bytes.
   * @return A base58check encoded string.
   */
  base58CheckEncode(bytes: Uint8Array, prefix: Uint8Array): string {
    const prefixedBytes = this.mergeBytes(prefix, bytes)
    return base58Check.encode(prefixedBytes)
  },

  /**
   * Merge the given bytes.
   */
  mergeBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const merged = new Uint8Array(a.length + b.length)
    merged.set(a)
    merged.set(b, a.length)

    return merged
  },

  /**
   * Check if the given string is valid hex.
   *
   * @param input The input to check.
   * @returns true if the input is valid hex, otherwise false.
   */
  isHex(input: string): boolean {
    const hexRegEx = /([0-9]|[a-f])/gim
    return (input.match(hexRegEx) || []).length === input.length
  },

  /**
   * Convert the given hex string to bytes.
   */
  hexToBytes(hex: string): Uint8Array {
    if (!this.isHex(hex)) {
      throw new Error(`Invalid hex${hex}`)
    }

    return Uint8Array.from(Buffer.from(hex, 'hex'))
  },
}

export default utils
