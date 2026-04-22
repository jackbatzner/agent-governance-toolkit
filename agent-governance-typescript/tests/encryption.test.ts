// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for E2E encryption modules (X3DH, Double Ratchet, SecureChannel).
 *
 * Implements against: docs/specs/AGENTMESH-WIRE-1.0.md
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/ciphers/utils";
import {
  X3DHKeyManager,
  generateX25519KeyPair,
  ed25519ToX25519,
  DoubleRatchet,
  SecureChannel,
} from "../src/encryption";

function makeManager(): X3DHKeyManager {
  const priv = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(priv);
  return new X3DHKeyManager(priv, pub);
}

function setupPair(): [DoubleRatchet, DoubleRatchet] {
  const alice = makeManager();
  const bob = makeManager();

  bob.generateSignedPreKey();
  bob.generateOneTimePreKeys(1);
  const bobBundle = bob.getPublicBundle(0);

  const aliceResult = alice.initiate(bobBundle);
  const bobResult = bob.respond(
    alice.identityKey.publicKey,
    aliceResult.ephemeralPublicKey,
    aliceResult.usedOneTimeKeyId,
  );

  const aliceRatchet = DoubleRatchet.initSender(
    aliceResult.sharedSecret,
    bobBundle.signedPreKey,
  );
  const bobRatchet = DoubleRatchet.initReceiver(bobResult.sharedSecret, {
    privateKey: bob.signedPreKey!.keyPair.privateKey,
    publicKey: bob.signedPreKey!.keyPair.publicKey,
  });
  return [aliceRatchet, bobRatchet];
}

const enc = new TextEncoder();
const dec = new TextDecoder();

// ── X25519 Key Pair ──

describe("X25519KeyPair", () => {
  test("generate produces 32-byte keys", () => {
    const kp = generateX25519KeyPair();
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  test("generate produces unique keys", () => {
    const kp1 = generateX25519KeyPair();
    const kp2 = generateX25519KeyPair();
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(false);
  });

  test("ed25519 to x25519 conversion", () => {
    const priv = ed25519.utils.randomSecretKey();
    const pub = ed25519.getPublicKey(priv);
    const kp = ed25519ToX25519(priv, pub);
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });
});

describe("X3DH", () => {
  test("shared secret matches on both sides", () => {
    const alice = makeManager();
    const bob = makeManager();

    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(5);
    const bundle = bob.getPublicBundle(3);

    const a = alice.initiate(bundle);
    const b = bob.respond(alice.identityKey.publicKey, a.ephemeralPublicKey, a.usedOneTimeKeyId);

    expect(Buffer.from(a.sharedSecret).equals(Buffer.from(b.sharedSecret))).toBe(true);
    expect(a.usedOneTimeKeyId).toBe(3);
    expect(Buffer.from(a.associatedData).equals(Buffer.from(b.associatedData))).toBe(true);
  });

  test("one-time pre-key is consumed after use", () => {
    const alice = makeManager();
    const bob = makeManager();

    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const bundle = bob.getPublicBundle(1);

    const a = alice.initiate(bundle);
    bob.respond(alice.identityKey.publicKey, a.ephemeralPublicKey, a.usedOneTimeKeyId);

    expect(bob.oneTimePreKeys.has(1)).toBe(false);
  });

  test("invalid signed pre-key signature is rejected", () => {
    const alice = makeManager();
    const bob = makeManager();

    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    bundle.signedPreKeySignature[0] ^= 0xff;

    expect(() => alice.initiate(bundle)).toThrow("Invalid signed pre-key signature");
  });
});

describe("DoubleRatchet", () => {
  test("one-way message exchange", () => {
    const [alice, bob] = setupPair();

    const msg = alice.encrypt(enc.encode("hello"));
    const pt = bob.decrypt(msg);

    expect(dec.decode(pt)).toBe("hello");
  });

  test("bidirectional conversation", () => {
    const [alice, bob] = setupPair();

    const m1 = alice.encrypt(enc.encode("ping"));
    expect(dec.decode(bob.decrypt(m1))).toBe("ping");

    const m2 = bob.encrypt(enc.encode("pong"));
    expect(dec.decode(alice.decrypt(m2))).toBe("pong");

    const m3 = alice.encrypt(enc.encode("done"));
    expect(dec.decode(bob.decrypt(m3))).toBe("done");
  });

  test("out-of-order messages with skipped keys", () => {
    const [alice, bob] = setupPair();

    const m1 = alice.encrypt(enc.encode("msg1"));
    const m2 = alice.encrypt(enc.encode("msg2"));
    const m3 = alice.encrypt(enc.encode("msg3"));

    expect(dec.decode(bob.decrypt(m3))).toBe("msg3");
    expect(dec.decode(bob.decrypt(m1))).toBe("msg1");
    expect(dec.decode(bob.decrypt(m2))).toBe("msg2");
  });

  test("AAD integrity is enforced", () => {
    const [alice, bob] = setupPair();

    const aad = enc.encode("header-data");
    const msg = alice.encrypt(enc.encode("secret"), aad);

    expect(() => bob.decrypt(msg, enc.encode("wrong-aad"))).toThrow();
    expect(dec.decode(bob.decrypt(msg, aad))).toBe("secret");
  });

  test("too many skipped messages is rejected", () => {
    const [alice, bob] = setupPair();

    let last;
    for (let i = 0; i < 101; i += 1) {
      last = alice.encrypt(enc.encode(`msg${i}`));
    }

    expect(() => bob.decrypt(last!)).toThrow("Too many skipped messages");
  });
});

describe("SecureChannel", () => {
  test("alice ↔ bob encrypted channel", () => {
    const alice = makeManager();
    const bob = makeManager();

    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);

    const bundle = bob.getPublicBundle(0);
    const aliceCh = SecureChannel.createInitiator(alice, bundle);
    const bobCh = SecureChannel.createResponder(
      bob,
      alice.identityKey.publicKey,
      aliceCh.getInitialEphemeralKey(),
      aliceCh.getUsedOneTimeKeyId(),
    );

    const c1 = aliceCh.send("hello bob");
    expect(bobCh.receive(c1)).toBe("hello bob");

    const c2 = bobCh.send("hi alice");
    expect(aliceCh.receive(c2)).toBe("hi alice");
  });

  test("channel message JSON roundtrip", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();

    const aliceCh = SecureChannel.createInitiator(alice, bundle);
    const bobCh = SecureChannel.createResponder(
      bob,
      alice.identityKey.publicKey,
      aliceCh.getInitialEphemeralKey(),
      aliceCh.getUsedOneTimeKeyId(),
    );

    const msg = aliceCh.send("json-roundtrip");
    const serialized = SecureChannel.serialize(msg);
    const parsed = SecureChannel.deserialize(serialized);

    expect(bobCh.receive(parsed)).toBe("json-roundtrip");
  });

  test("tampering is detected", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();

    const aliceCh = SecureChannel.createInitiator(alice, bundle);
    const bobCh = SecureChannel.createResponder(
      bob,
      alice.identityKey.publicKey,
      aliceCh.getInitialEphemeralKey(),
      aliceCh.getUsedOneTimeKeyId(),
    );

    const msg = aliceCh.send("untampered");
    msg.ciphertext[msg.ciphertext.length - 1] ^= 0xff;

    expect(() => bobCh.receive(msg)).toThrow();
  });

  test("large payload", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();

    const aliceCh = SecureChannel.createInitiator(alice, bundle);
    const bobCh = SecureChannel.createResponder(
      bob,
      alice.identityKey.publicKey,
      aliceCh.getInitialEphemeralKey(),
      aliceCh.getUsedOneTimeKeyId(),
    );

    const payload = Buffer.from(randomBytes(4096)).toString("base64");
    const msg = aliceCh.send(payload);
    expect(bobCh.receive(msg)).toBe(payload);
  });
});
