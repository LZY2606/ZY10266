/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Version.V3;
import static org.paseto4j.version3.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version3.CryptoFunctions.hmac384;
import static org.paseto4j.version3.CryptoFunctions.randomBytes;

import java.security.MessageDigest;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.LocalCipher;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.Pair;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private PasetoLocal() {}

  private static final LocalCipher CIPHER = new V3LocalCipher();

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, randomBytes(32), payload, footer, implicit);
  }

  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicit) {
    return LocalTokenPipeline.encrypt(V3, CIPHER, key, nonce, payload, footer, implicit);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token) {
    return decrypt(key, token, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    return LocalTokenPipeline.decrypt(V3, CIPHER, key, token, footer, implicitAssertion);
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

  /**
   * Version 3 crypto primitives: AES-CTR with HMAC-SHA384, PAE(header, nonce, c, footer,
   * implicit).
   */
  private static final class V3LocalCipher implements LocalCipher {

    @Override
    public int nonceLength() {
      return 32;
    }

    @Override
    public int tagLength() {
      return 48;
    }

    @Override
    public byte[] nonce(byte[] payload, byte[] random) {
      return random;
    }

    @Override
    public byte[][] preAuthPieces(
        byte[] header, byte[] nonce, byte[] cipherText, byte[] footer, byte[] implicitAssertion) {
      return new byte[][] {header, nonce, cipherText, footer, implicitAssertion};
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] nonce, byte[] payload, byte[] preAuth) {
      byte[] tmp = encryptionKey(key, nonce);
      Pair<byte[]> split = ByteUtils.split(tmp, 32);
      byte[] ek = split.getFirst();
      byte[] n2 = split.getSecond();
      try {
        return encryptAesCtr(ek, n2, payload);
      } finally {
        wipe(tmp, ek, n2);
      }
    }

    @Override
    public byte[] tag(SecretKey key, byte[] nonce, byte[] preAuth) {
      byte[] ak = authenticationKey(key, nonce);
      try {
        return hmac384(ak, preAuth);
      } finally {
        wipe(ak);
      }
    }

    @Override
    public byte[] decrypt(SecretKey key, byte[] nonce, byte[] cipherText, byte[] tag, byte[] preAuth) {
      byte[] tmp = encryptionKey(key, nonce);
      Pair<byte[]> split = ByteUtils.split(tmp, 32);
      byte[] ek = split.getFirst();
      byte[] n2 = split.getSecond();
      byte[] ak = authenticationKey(key, nonce);
      try {
        byte[] expectedTag = hmac384(ak, preAuth);
        if (!MessageDigest.isEqual(tag, expectedTag)) {
          throw new IllegalStateException("HMAC verification failed");
        }
        return decryptAesCtr(ek, n2, cipherText);
      } finally {
        wipe(tmp, ek, n2, ak);
      }
    }
  }
}
