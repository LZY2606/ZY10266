/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Version.V1;
import static org.paseto4j.version1.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version1.CryptoFunctions.hmac384;
import static org.paseto4j.version1.CryptoFunctions.randomBytes;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.LocalCipher;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private PasetoLocal() {}

  private static final LocalCipher CIPHER = new V1LocalCipher();

  public static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, randomBytes(), payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    return LocalTokenPipeline.encrypt(V1, CIPHER, key, randomKey, payload, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt">...</a>
   */
  static String decrypt(SecretKey key, String token, String footer) {
    return LocalTokenPipeline.decrypt(V1, CIPHER, key, token, footer, "");
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(
          rawKey, Arrays.copyOfRange(nonce, 0, 16), "paseto-encryption-key".getBytes(UTF_8));
    } finally {
      wipe(rawKey);
    }
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(
          rawKey, Arrays.copyOfRange(nonce, 0, 16), "paseto-auth-key-for-aead".getBytes(UTF_8));
    } finally {
      wipe(rawKey);
    }
  }

  /** Version 1 crypto primitives: AES-CTR with HMAC-SHA384, PAE(header, nonce, c, footer). */
  private static final class V1LocalCipher implements LocalCipher {

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
      return Arrays.copyOfRange(hmac384(random, payload), 0, 32);
    }

    @Override
    public byte[][] preAuthPieces(
        byte[] header, byte[] nonce, byte[] cipherText, byte[] footer, byte[] implicitAssertion) {
      return new byte[][] {header, nonce, cipherText, footer};
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] nonce, byte[] payload, byte[] preAuth) {
      byte[] ek = encryptionKey(key, nonce);
      try {
        return encryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), payload);
      } finally {
        wipe(ek);
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
      byte[] ek = encryptionKey(key, nonce);
      byte[] ak = authenticationKey(key, nonce);
      try {
        byte[] expectedTag = hmac384(ak, preAuth);
        if (!MessageDigest.isEqual(tag, expectedTag)) {
          throw new IllegalStateException("HMAC verification failed");
        }
        return decryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), cipherText);
      } finally {
        wipe(ek, ak);
      }
    }
  }
}
