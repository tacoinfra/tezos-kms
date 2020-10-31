/** Disable some linting rules to allow use of untyped JS libs. */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-var-requires */

import Prefixes from './prefixes'
import ASN1 from './asn1'
import { KMS } from 'aws-sdk'
import Utils from './utils'

// AWS KMS Signing Algorithm.
const SIGNING_ALGORITHM = 'ECDSA_SHA_256'

// Length of hash for signing in Tezos.
const DIGEST_LENGTH = 32

// Length of the public key hash for signing in Tezos.
const PUBLIC_KEY_HASH_LENGTH = 20

/** Provides capabilities for working with Tezos Keys stored in AWS KMS. */
export default class TezosKmsClient {
  private readonly kms: KMS
  private readonly kmsKeyId: string

  /**
   * Initialize a new TezosKmsClient.
   *
   * @param kmsKeyId The identifier of the KMS Key ID.
   * @param region The region the KMS key is in.
   */
  public constructor(kmsKeyId: string, region: string) {
    this.kms = new KMS({
      region,
    })
    this.kmsKeyId = kmsKeyId
  }

  /**
   * Retrieve the public key from KMS.
   *
   * @returns The public key in a base58check encoded format.
   */
  public async getPublicKey(): Promise<string> {
    const publicKeyResponse = await this.kms
      .getPublicKey({
        KeyId: this.kmsKeyId,
      })
      .promise()

    const publicKeyDer = publicKeyResponse.PublicKey
    if (publicKeyDer === undefined) {
      throw new Error("Couldn't retreive key from AWS KMS")
    }

    const decodedPublicKey = ASN1.decode(publicKeyDer)
    const publicKeyHex = decodedPublicKey.sub[1].toHexStringContent()
    const uncompressedPublicKeyBytes = Utils.hexToBytes(publicKeyHex)
    const publicKeyBytes = Utils.compressKey(uncompressedPublicKeyBytes)

    return Utils.base58CheckEncode(publicKeyBytes, Prefixes.secp256k1PublicKey)
  }

  /**
   * Retrieve the public key hash from KMS.
   *
   * @returns The public key hash in a base58check encoded format.
   */
  public async getPublicKeyHash(): Promise<string> {
    const publicKeyResponse = await this.kms
      .getPublicKey({
        KeyId: this.kmsKeyId,
      })
      .promise()

    const publicKeyDer = publicKeyResponse.PublicKey
    if (publicKeyDer === undefined) {
      throw new Error("Couldn't retreive key from AWS KMS")
    }

    const decodedPublicKey = ASN1.decode(publicKeyDer)
    const publicKeyHex = decodedPublicKey.sub[1].toHexStringContent()
    const uncompressedPublicKeyBytes = Utils.hexToBytes(publicKeyHex)
    const publicKeyBytes = Utils.compressKey(uncompressedPublicKeyBytes)

    return Utils.base58CheckEncode(
      Utils.blake2b(publicKeyBytes, PUBLIC_KEY_HASH_LENGTH),
      Prefixes.secp256k1PublicKeyHash,
    )
  }

  /**
   * Sign the given bytes with the KMS key.
   *
   * This method will compute a digest, of the input bytes, sign them, and return the
   * bytes representing the raw signature.
   *
   * @param bytes The raw bytes.
   * @returns A base58check encoded signature.
   */
  public async signOperation(bytes: Buffer): Promise<Buffer> {
    const digest = Utils.blake2b(bytes, DIGEST_LENGTH)

    const params = {
      KeyId: this.kmsKeyId,
      Message: digest,
      SigningAlgorithm: SIGNING_ALGORITHM,
      MessageType: 'DIGEST',
    }

    const { Signature: derSignature } = await this.kms.sign(params).promise()
    if (!(derSignature instanceof Uint8Array)) {
      throw new Error('Unexpected response from KMS')
    }

    const rawSignature = Utils.derSignatureToRaw(derSignature)
    const normalizedSignature = Utils.normalizeSignature(rawSignature)
    return Buffer.from(normalizedSignature)
  }

  /**
   * Sign the given bytes with the KMS key.
   *
   * This method will compute a digest, of the input bytes, sign them, and return the
   * a base58check encoded signature.
   *
   * @param bytes The raw bytes.
   * @returns A base58check encoded signature.
   */
  public async signOperationBase58(bytes: Buffer): Promise<string> {
    const signatureBytes = await this.signOperation(bytes)

    return Utils.base58CheckEncode(signatureBytes, Prefixes.secp256k1signature)
  }
}
