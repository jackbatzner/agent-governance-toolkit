// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Double Ratchet algorithm for per-message forward secrecy.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 8
 * Reference: https://signal.org/docs/specifications/doubleratchet/ (CC0)
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/ciphers/utils";

const KDF_INFO_RATCHET = new TextEncoder().encode("AgentMesh_Ratchet_v1");
const NONCE_LEN = 12;
const KEY_LEN = 32;
const MAX_SKIP = 100;

export interface MessageHeader {
  dhPublicKey: Uint8Array;
  previousChainLength: number;
  messageNumber: number;
}

export interface EncryptedMessage {
  header: MessageHeader;
  ciphertext: Uint8Array;
}

export interface RatchetState {
  dhSelfPrivate: Uint8Array;
  dhSelfPublic: Uint8Array;
  dhRemotePublic: Uint8Array | null;
  rootKey: Uint8Array;
  chainKeySend: Uint8Array | null;
  chainKeyRecv: Uint8Array | null;
  sendMessageNumber: number;
  recvMessageNumber: number;
  previousSendChainLength: number;
  skippedKeys: Map<string, Uint8Array>;
}

function generateDHPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = randomBytes(KEY_LEN);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const derived = hkdf(sha256, dhOutput, rootKey, KDF_INFO_RATCHET, 64);
  return [derived.slice(0, 32), derived.slice(32)];
}

function kdfChain(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const messageKey = hmac(sha256, chainKey, new Uint8Array([0x01]));
  const nextChainKey = hmac(sha256, chainKey, new Uint8Array([0x02]));
  return [messageKey, nextChainKey];
}

function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = chacha20poly1305(key, nonce, aad);
  const ct = cipher.encrypt(plaintext);
  const result = new Uint8Array(NONCE_LEN + ct.length);
  result.set(nonce, 0);
  result.set(ct, NONCE_LEN);
  return result;
}

function decrypt(key: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  if (data.length < NONCE_LEN) throw new Error("Ciphertext too short");
  const nonce = data.slice(0, NONCE_LEN);
  const ct = data.slice(NONCE_LEN);
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ct);
}

function skippedKeyId(pubKey: Uint8Array, n: number): string {
  return `${Buffer.from(pubKey).toString("hex")}:${n}`;
}

export class DoubleRatchet {
  private state: RatchetState;

  private constructor(state: RatchetState) {
    this.state = state;
  }

  static initSender(
    sharedSecret: Uint8Array,
    receiverPublicKey: Uint8Array,
  ): DoubleRatchet {
    const dhPair = generateDHPair();
    const [rootKey, chainKeySend] = kdfRoot(sharedSecret, x25519.getSharedSecret(dhPair.privateKey, receiverPublicKey));

    return new DoubleRatchet({
      dhSelfPrivate: dhPair.privateKey,
      dhSelfPublic: dhPair.publicKey,
      dhRemotePublic: receiverPublicKey,
      rootKey,
      chainKeySend,
      chainKeyRecv: null,
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      previousSendChainLength: 0,
      skippedKeys: new Map(),
    });
  }

  static initReceiver(
    sharedSecret: Uint8Array,
    receiverKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array },
  ): DoubleRatchet {
    return new DoubleRatchet({
      dhSelfPrivate: receiverKeyPair.privateKey,
      dhSelfPublic: receiverKeyPair.publicKey,
      dhRemotePublic: null,
      rootKey: sharedSecret,
      chainKeySend: null,
      chainKeyRecv: null,
      sendMessageNumber: 0,
      recvMessageNumber: 0,
      previousSendChainLength: 0,
      skippedKeys: new Map(),
    });
  }

  encrypt(plaintext: Uint8Array, aad: Uint8Array = new Uint8Array(0)): EncryptedMessage {
    if (!this.state.chainKeySend) {
      throw new Error("Cannot encrypt: send chain not initialized");
    }

    const [messageKey, nextChainKey] = kdfChain(this.state.chainKeySend);
    this.state.chainKeySend = nextChainKey;

    const header: MessageHeader = {
      dhPublicKey: this.state.dhSelfPublic,
      previousChainLength: this.state.previousSendChainLength,
      messageNumber: this.state.sendMessageNumber,
    };

    const headerBytes = this.serializeHeader(header);
    const fullAad = this.concat(aad, headerBytes);
    const ciphertext = encrypt(messageKey, plaintext, fullAad);

    this.state.sendMessageNumber += 1;

    return { header, ciphertext };
  }

  decrypt(message: EncryptedMessage, aad: Uint8Array = new Uint8Array(0)): Uint8Array {
    const headerKeyId = skippedKeyId(message.header.dhPublicKey, message.header.messageNumber);
    const skipped = this.state.skippedKeys.get(headerKeyId);
    if (skipped) {
      this.state.skippedKeys.delete(headerKeyId);
      const headerBytes = this.serializeHeader(message.header);
      return decrypt(skipped, message.ciphertext, this.concat(aad, headerBytes));
    }

    if (!this.state.dhRemotePublic || !this.equal(this.state.dhRemotePublic, message.header.dhPublicKey)) {
      this.skipMessageKeys(message.header.previousChainLength);
      this.dhRatchet(message.header.dhPublicKey);
    }

    this.skipMessageKeys(message.header.messageNumber);

    if (!this.state.chainKeyRecv) {
      throw new Error("Cannot decrypt: receive chain not initialized");
    }

    const [messageKey, nextChainKey] = kdfChain(this.state.chainKeyRecv);
    this.state.chainKeyRecv = nextChainKey;
    this.state.recvMessageNumber += 1;

    const headerBytes = this.serializeHeader(message.header);
    return decrypt(messageKey, message.ciphertext, this.concat(aad, headerBytes));
  }

  private dhRatchet(newRemotePublicKey: Uint8Array): void {
    this.state.previousSendChainLength = this.state.sendMessageNumber;
    this.state.sendMessageNumber = 0;
    this.state.recvMessageNumber = 0;

    this.state.dhRemotePublic = newRemotePublicKey;

    const [rootKey1, chainKeyRecv] = kdfRoot(
      this.state.rootKey,
      x25519.getSharedSecret(this.state.dhSelfPrivate, newRemotePublicKey),
    );

    const newDhPair = generateDHPair();
    const [rootKey2, chainKeySend] = kdfRoot(
      rootKey1,
      x25519.getSharedSecret(newDhPair.privateKey, newRemotePublicKey),
    );

    this.state.rootKey = rootKey2;
    this.state.chainKeyRecv = chainKeyRecv;
    this.state.chainKeySend = chainKeySend;
    this.state.dhSelfPrivate = newDhPair.privateKey;
    this.state.dhSelfPublic = newDhPair.publicKey;
  }

  private skipMessageKeys(until: number): void {
    if (this.state.recvMessageNumber + MAX_SKIP < until) {
      throw new Error(`Too many skipped messages: ${until - this.state.recvMessageNumber} > ${MAX_SKIP}`);
    }

    while (this.state.chainKeyRecv && this.state.recvMessageNumber < until) {
      const [messageKey, nextChainKey] = kdfChain(this.state.chainKeyRecv);
      const keyId = skippedKeyId(this.state.dhRemotePublic!, this.state.recvMessageNumber);
      this.state.skippedKeys.set(keyId, messageKey);
      this.state.chainKeyRecv = nextChainKey;
      this.state.recvMessageNumber += 1;
    }
  }

  private serializeHeader(header: MessageHeader): Uint8Array {
    const result = new Uint8Array(32 + 4 + 4);
    result.set(header.dhPublicKey, 0);
    const view = new DataView(result.buffer);
    view.setUint32(32, header.previousChainLength, false);
    view.setUint32(36, header.messageNumber, false);
    return result;
  }

  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  private equal(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}
