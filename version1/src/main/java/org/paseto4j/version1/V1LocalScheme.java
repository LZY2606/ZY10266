/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V1;
import static org.paseto4j.version1.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version1.CryptoFunctions.hmac384;

import java.security.MessageDigest;
import java.util.Arrays;
import org.paseto4j.commons.LocalScheme;
import org.paseto4j.commons.LocalSegments;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 1 local scheme: AES-CTR with HMAC-SHA384 (encrypt-then-MAC). */
class V1LocalScheme implements LocalScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V1, PURPOSE_LOCAL);
  private static final PayloadLayout LAYOUT = PayloadLayout.local(32, 48);

  private final SecretKey key;
  private final byte[] randomKey;

  V1LocalScheme(SecretKey key) {
    this(key, null);
  }

  V1LocalScheme(SecretKey key, byte[] randomKey) {
    this.key = key;
    this.randomKey = randomKey;
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
    // 3
    byte[] nonce = getNonce(payload, randomKey);

    // 4
    byte[] ek = encryptionKey(nonce);
    byte[] ak = authenticationKey(nonce);

    // 5
    byte[] cipherText = encryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), payload);

    // 6
    byte[] preAuth = encode(header, nonce, cipherText, footer);

    // 7
    byte[] tag = hmac384(ak, preAuth);

    // 8
    return concat(nonce, cipherText, tag);
  }

  @Override
  public byte[] decrypt(
      LocalSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion) {
    byte[] nonce = segments.nonce();

    // 4
    byte[] ek = encryptionKey(nonce);
    byte[] ak = authenticationKey(nonce);

    // 5
    byte[] preAuth = encode(header, nonce, segments.cipherText(), footer);

    // 6
    byte[] expectedTag = hmac384(ak, preAuth);

    // 7
    if (!MessageDigest.isEqual(segments.tag(), expectedTag)) {
      throw new IllegalStateException("HMAC verification failed");
    }

    // 8
    return decryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), segments.cipherText());
  }

  private static byte[] getNonce(byte[] payload, byte[] randomKey) {
    return Arrays.copyOfRange(CryptoFunctions.hmac384(randomKey, payload), 0, 32);
  }

  private byte[] encryptionKey(byte[] nonce) {
    return hkdfSha384(
        key.toBytes(), Arrays.copyOfRange(nonce, 0, 16), "paseto-encryption-key".getBytes(UTF_8));
  }

  private byte[] authenticationKey(byte[] nonce) {
    return hkdfSha384(
        key.toBytes(),
        Arrays.copyOfRange(nonce, 0, 16),
        "paseto-auth-key-for-aead".getBytes(UTF_8));
  }
}
