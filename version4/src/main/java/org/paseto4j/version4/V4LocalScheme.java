/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V4;

import java.security.MessageDigest;
import java.util.Arrays;
import org.paseto4j.commons.LocalScheme;
import org.paseto4j.commons.LocalSegments;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 4 local scheme: XChaCha20 with keyed BLAKE2b (encrypt-then-MAC). */
class V4LocalScheme implements LocalScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V4, PURPOSE_LOCAL);
  private static final PayloadLayout LAYOUT = PayloadLayout.local(32, 32);

  private final SecretKey key;
  private final byte[] nonce;

  V4LocalScheme(SecretKey key) {
    this(key, null);
  }

  V4LocalScheme(SecretKey key, byte[] nonce) {
    this.key = key;
    this.nonce = nonce;
  }

  @Override
  public TokenAlgorithm algorithm() {
    return ALGORITHM;
  }

  @Override
  public PayloadLayout layout() {
    return LAYOUT;
  }

  @Override
  public byte[] encrypt(byte[] payload, byte[] header, byte[] footer, byte[] implicitAssertion) {
    // 4
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);
    try {
      // 5
      byte[] c = CryptoFunctions.xchacha20(payload, n2, ek);

      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(header, nonce, c, footer, implicitAssertion);

      // 7
      byte[] t = CryptoFunctions.blake2b(32, preAuth, ak);

      return concat(nonce, c, t);
    } finally {
      wipe(tmp, ek, n2, ak);
    }
  }

  @Override
  public byte[] decrypt(
      LocalSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion) {
    byte[] nonce = segments.nonce();
    byte[] c = segments.cipherText();

    // 5
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);
    byte[] message = null;
    try {
      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(header, nonce, c, footer, implicitAssertion);

      // 7
      byte[] t2 = CryptoFunctions.blake2b(32, preAuth, ak);

      // 8
      if (!MessageDigest.isEqual(segments.tag(), t2)) {
        throw new IllegalStateException("HMAC verification failed");
      }

      message = CryptoFunctions.xchacha20(c, n2, ek);
      return message.clone();
    } finally {
      wipe(tmp, ek, n2, ak, message);
    }
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return CryptoFunctions.blake2b(
          56, concat("paseto-encryption-key".getBytes(UTF_8), nonce), rawKey);
    } finally {
      wipe(rawKey);
    }
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return CryptoFunctions.blake2b(
          32, concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce), rawKey);
    } finally {
      wipe(rawKey);
    }
  }
}
