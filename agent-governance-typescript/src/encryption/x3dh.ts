// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 *
 * Implements the Signal X3DH specification for establishing shared secrets
 * between agents. Uses Ed25519 identity keys converted to X25519 for DH.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 7
 * Reference: https://signal.org/docs/specifications/x3dh/ (CC0)
 */

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/ciphers/utils";

const X3DH_INFO = new TextEncoder().encode("AgentMesh_X3DH_v1");
const KEY_LEN = 32;
const FF_SALT = new Uint8Array(32).fill(0xff);

export interface X25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface PreKeyBundle {
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  signedPreKeyId: number;
  oneTimePreKey?: Uint8Array;
  oneTimePreKeyId?: number;
}

export interface X3DHResult {
  sharedSecret: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  usedOneTimeKeyId?: number;
  associatedData: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = randomBytes(KEY_LEN);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function ed25519ToX25519(
  ed25519Private: Uint8Array,
  ed25519Public: Uint8Array,
): X25519KeyPair {
  if (ed25519Public.length !== 32) {
    throw new Error("ed25519Public must be 32 bytes");
  }
  if (ed25519Private.length !== 32 && ed25519Private.length !== 64) {
    throw new Error("ed25519Private must be 32 or 64 bytes");
  }
  const priv32 = ed25519Private.length === 64 ? ed25519Private.slice(0, 32) : ed25519Private;
  // Ed25519 seed → SHA-512 → first 32 bytes → clamp per RFC 7748 §5
  const h = sha512(priv32);
  const privateKey = h.slice(0, 32);
  privateKey[0] &= 248;
  privateKey[31] &= 127;
  privateKey[31] |= 64;
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function kdf(ikm: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, FF_SALT, X3DH_INFO, KEY_LEN);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export class X3DHKeyManager {
  readonly identityKey: X25519KeyPair;
  readonly identityEd25519: { privateKey: Uint8Array; publicKey: Uint8Array };
  signedPreKey?: {
    keyPair: X25519KeyPair;
    id: number;
    signature: Uint8Array;
  };
  oneTimePreKeys = new Map<number, X25519KeyPair>();
  private nextPreKeyId = 1;

  constructor(identityPrivateEd25519: Uint8Array, identityPublicEd25519: Uint8Array) {
    this.identityEd25519 = {
      privateKey: identityPrivateEd25519,
      publicKey: identityPublicEd25519,
    };
    this.identityKey = ed25519ToX25519(identityPrivateEd25519, identityPublicEd25519);
  }

  generateSignedPreKey(): void {
    const keyPair = generateX25519KeyPair();
    const signature = ed25519.sign(keyPair.publicKey, this.identityEd25519.privateKey);
    this.signedPreKey = {
      keyPair,
      id: this.nextPreKeyId++,
      signature,
    };
  }

  generateOneTimePreKeys(count: number): void {
    for (let i = 0; i < count; i += 1) {
      this.oneTimePreKeys.set(this.nextPreKeyId++, generateX25519KeyPair());
    }
  }

  getPublicBundle(oneTimePreKeyId?: number): PreKeyBundle {
    if (!this.signedPreKey) {
      throw new Error("Signed pre-key not generated");
    }
    const bundle: PreKeyBundle = {
      identityKey: this.identityKey.publicKey,
      signedPreKey: this.signedPreKey.keyPair.publicKey,
      signedPreKeySignature: this.signedPreKey.signature,
      signedPreKeyId: this.signedPreKey.id,
    };
    if (oneTimePreKeyId !== undefined) {
      const oneTime = this.oneTimePreKeys.get(oneTimePreKeyId);
      if (oneTime) {
        bundle.oneTimePreKey = oneTime.publicKey;
        bundle.oneTimePreKeyId = oneTimePreKeyId;
      }
    }
    return bundle;
  }

  initiate(recipientBundle: PreKeyBundle): X3DHResult {
    const isValid = ed25519.verify(
      recipientBundle.signedPreKeySignature,
      recipientBundle.signedPreKey,
      recipientBundle.identityKey,
    );
    if (!isValid) {
      throw new Error("Invalid signed pre-key signature");
    }

    const eph = generateX25519KeyPair();

    const dh1 = x25519.getSharedSecret(this.identityKey.privateKey, recipientBundle.signedPreKey);
    const dh2 = x25519.getSharedSecret(eph.privateKey, recipientBundle.identityKey);
    const dh3 = x25519.getSharedSecret(eph.privateKey, recipientBundle.signedPreKey);

    const parts = [dh1, dh2, dh3];
    if (recipientBundle.oneTimePreKey) {
      const dh4 = x25519.getSharedSecret(eph.privateKey, recipientBundle.oneTimePreKey);
      parts.push(dh4);
    }

    const dhConcat = concat(...parts);
    const sharedSecret = kdf(dhConcat);
    const associatedData = concat(this.identityKey.publicKey, recipientBundle.identityKey);

    return {
      sharedSecret,
      ephemeralPublicKey: eph.publicKey,
      usedOneTimeKeyId: recipientBundle.oneTimePreKeyId,
      associatedData,
    };
  }

  respond(
    initiatorIdentityKey: Uint8Array,
    initiatorEphemeralKey: Uint8Array,
    oneTimePreKeyId?: number,
  ): X3DHResult {
    if (!this.signedPreKey) {
      throw new Error("Signed pre-key not generated");
    }

    const dh1 = x25519.getSharedSecret(this.signedPreKey.keyPair.privateKey, initiatorIdentityKey);
    const dh2 = x25519.getSharedSecret(this.identityKey.privateKey, initiatorEphemeralKey);
    const dh3 = x25519.getSharedSecret(this.signedPreKey.keyPair.privateKey, initiatorEphemeralKey);

    const parts = [dh1, dh2, dh3];
    if (oneTimePreKeyId !== undefined) {
      const oneTimePreKey = this.oneTimePreKeys.get(oneTimePreKeyId);
      if (!oneTimePreKey) {
        throw new Error(`One-time pre-key ${oneTimePreKeyId} not found`);
      }
      const dh4 = x25519.getSharedSecret(oneTimePreKey.privateKey, initiatorEphemeralKey);
      parts.push(dh4);
      this.oneTimePreKeys.delete(oneTimePreKeyId);
    }

    const dhConcat = concat(...parts);
    const sharedSecret = kdf(dhConcat);
    const associatedData = concat(initiatorIdentityKey, this.identityKey.publicKey);

    return {
      sharedSecret,
      ephemeralPublicKey: initiatorEphemeralKey,
      usedOneTimeKeyId: oneTimePreKeyId,
      associatedData,
    };
  }
}
