/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V3;
import static org.paseto4j.version3.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version3.CryptoFunctions.hmac384;

import java.security.MessageDigest;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.LocalScheme;
import org.paseto4j.commons.LocalSegments;
import org.paseto4j.commons.Pair;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 3 local scheme: AES-CTR with HMAC-SHA384 (encrypt-then-MAC). */
class V3LocalScheme implements LocalScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V3, PURPOSE_LOCAL);
  private static final PayloadLayout LAYOUT = PayloadLayout.local(32, 48);

  private final SecretKey key;
  private final byte[] nonce;

  V3LocalScheme(SecretKey key) {
    this(key, null);
  }

  V3LocalScheme(SecretKey key, byte[] nonce) {
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
    Pair<byte[]> split = ByteUtils.split(tmp, 32);
    byte[] ek = split.getFirst();
    byte[] n2 = split.getSecond();
    byte[] ak = authenticationKey(key, nonce);
    try {
      // 5
      byte[] cipherText = encryptAesCtr(ek, n2, payload);

      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(header, nonce, cipherText, footer, implicitAssertion);

      // 7
      byte[] tag = hmac384(ak, preAuth);

      // 8
      return concat(nonce, cipherText, tag);
    } finally {
      wipe(tmp, ek, n2, ak);
    }
  }

  @Override
  public byte[] decrypt(
      LocalSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion) {
    byte[] nonce = segments.nonce();
    byte[] cipherText = segments.cipherText();

    // 5
    byte[] tmp = encryptionKey(key, nonce);
    Pair<byte[]> split = ByteUtils.split(tmp, 32);
    byte[] ek = split.getFirst();
    byte[] n2 = split.getSecond();
    byte[] ak = authenticationKey(key, nonce);
    byte[] message = null;
    try {
      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(header, nonce, cipherText, footer, implicitAssertion);

      // 7
      byte[] expectedTag = hmac384(ak, preAuth);

      // 8
      if (!MessageDigest.isEqual(segments.tag(), expectedTag)) {
        throw new IllegalStateException("HMAC verification failed");
      }

      // 9
      message = decryptAesCtr(ek, n2, cipherText);
      return message.clone();
    } finally {
      wipe(tmp, ek, n2, ak, message);
    }
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(rawKey, concat("paseto-encryption-key".getBytes(UTF_8), nonce));
    } finally {
      wipe(rawKey);
    }
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(rawKey, concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce));
    } finally {
      wipe(rawKey);
    }
  }
}
