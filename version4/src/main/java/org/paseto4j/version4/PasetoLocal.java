/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Version.V4;

import java.security.MessageDigest;
import java.util.Arrays;
import org.paseto4j.commons.LocalCipher;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

public class PasetoLocal {
  private PasetoLocal() {}

  private static final LocalCipher CIPHER = new V4LocalCipher();

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, CryptoFunctions.randomBytes(), payload, footer, implicit);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt">encrypt</a>
   */
  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicitAssertion) {
    return LocalTokenPipeline.encrypt(V4, CIPHER, key, nonce, payload, footer, implicitAssertion);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    return LocalTokenPipeline.decrypt(V4, CIPHER, key, token, footer, implicitAssertion);
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

  /**
   * Version 4 crypto primitives: XChaCha20 with keyed BLAKE2b, PAE(header, nonce, c, footer,
   * implicit).
   */
  private static final class V4LocalCipher implements LocalCipher {

    @Override
    public int nonceLength() {
      return 32;
    }

    @Override
    public int tagLength() {
      return 32;
    }

    @Override
    public byte[] nonce(byte[] payload, byte[] random) {
      verify(random.length == 32, "nonce should be 32 bytes");
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
      byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
      byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
      try {
        return CryptoFunctions.xchacha20(payload, n2, ek);
      } finally {
        wipe(tmp, ek, n2);
      }
    }

    @Override
    public byte[] tag(SecretKey key, byte[] nonce, byte[] preAuth) {
      byte[] ak = authenticationKey(key, nonce);
      try {
        return CryptoFunctions.blake2b(32, preAuth, ak);
      } finally {
        wipe(ak);
      }
    }

    @Override
    public byte[] decrypt(SecretKey key, byte[] nonce, byte[] cipherText, byte[] tag, byte[] preAuth) {
      byte[] tmp = encryptionKey(key, nonce);
      byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
      byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
      byte[] ak = authenticationKey(key, nonce);
      try {
        byte[] expectedTag = CryptoFunctions.blake2b(32, preAuth, ak);
        if (!MessageDigest.isEqual(tag, expectedTag)) {
          throw new IllegalStateException("HMAC verification failed");
        }
        return CryptoFunctions.xchacha20(cipherText, n2, ek);
      } finally {
        wipe(tmp, ek, n2, ak);
      }
    }
  }
}
