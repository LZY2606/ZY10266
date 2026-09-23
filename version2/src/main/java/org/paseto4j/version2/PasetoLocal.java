/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.AEAD;
import java.util.Arrays;
import org.paseto4j.commons.LocalCipher;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private PasetoLocal() {}

  private static final LocalCipher CIPHER = new V2LocalCipher();

  static String encrypt(SecretKey key, String payload, String footer) {
    byte[] randomKey = SODIUM.randomBytesBuf(32);
    return encrypt(key, randomKey, payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    return LocalTokenPipeline.encrypt(V2, CIPHER, key, randomKey, payload, footer, "");
  }

  static String decrypt(SecretKey key, String token, String footer) {
    return LocalTokenPipeline.decrypt(V2, CIPHER, key, token, footer, "");
  }

  /**
   * Version 2 crypto primitives: XChaCha20-Poly1305 AEAD with PAE(header, nonce, footer) as
   * additional data. The tag travels inside the AEAD output, so {@link #tagLength()} is 0.
   */
  private static final class V2LocalCipher implements LocalCipher {

    @Override
    public int nonceLength() {
      return AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES;
    }

    @Override
    public int tagLength() {
      return 0;
    }

    @Override
    public byte[] nonce(byte[] payload, byte[] random) {
      byte[] nonce = new byte[nonceLength()];
      SODIUM.cryptoGenericHash(nonce, nonce.length, payload, payload.length, random, random.length);
      return nonce;
    }

    @Override
    public byte[][] preAuthPieces(
        byte[] header, byte[] nonce, byte[] cipherText, byte[] footer, byte[] implicitAssertion) {
      return new byte[][] {header, nonce, footer};
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] nonce, byte[] payload, byte[] preAuth) {
      byte[] rawKey = key.toBytes();
      try {
        byte[] cipherText = new byte[payload.length + AEAD.XCHACHA20POLY1305_IETF_ABYTES];
        long[] cipherLen = new long[1];
        boolean success =
            SODIUM.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipherText,
                cipherLen,
                payload,
                payload.length,
                preAuth,
                preAuth.length,
                null,
                nonce,
                rawKey);
        if (!success) {
          throw new PasetoException("Encryption failed");
        }
        return cipherText;
      } finally {
        wipe(rawKey);
      }
    }

    @Override
    public byte[] tag(SecretKey key, byte[] nonce, byte[] preAuth) {
      throw new UnsupportedOperationException("v2 authenticates during encryption");
    }

    @Override
    public byte[] decrypt(SecretKey key, byte[] nonce, byte[] cipherText, byte[] tag, byte[] preAuth) {
      if (cipherText.length < AEAD.XCHACHA20POLY1305_IETF_ABYTES) {
        throw new PasetoException("Unable to decrypt the token");
      }
      byte[] rawKey = key.toBytes();
      try {
        byte[] message = new byte[cipherText.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
        long[] messageLen = new long[1];
        boolean success =
            SODIUM.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message,
                messageLen,
                null,
                cipherText,
                cipherText.length,
                preAuth,
                preAuth.length,
                nonce,
                rawKey);
        if (!success) {
          throw new PasetoException("Unable to decrypt the token");
        }
        return Arrays.copyOf(message, (int) messageLen[0]);
      } finally {
        wipe(rawKey);
      }
    }
  }
}
