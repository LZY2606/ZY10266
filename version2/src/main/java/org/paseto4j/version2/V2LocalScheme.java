/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.AEAD;
import java.util.Arrays;
import org.paseto4j.commons.LocalScheme;
import org.paseto4j.commons.LocalSegments;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 2 local scheme: XChaCha20-Poly1305 AEAD. */
class V2LocalScheme implements LocalScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V2, PURPOSE_LOCAL);
  private static final PayloadLayout LAYOUT =
      PayloadLayout.local(
          AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES, AEAD.XCHACHA20POLY1305_IETF_ABYTES);

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private final SecretKey key;
  private final byte[] randomKey;

  V2LocalScheme(SecretKey key) {
    this(key, null);
  }

  V2LocalScheme(SecretKey key, byte[] randomKey) {
    this.key = key;
    this.randomKey = randomKey;
  }

  static byte[] randomKey() {
    return SODIUM.randomBytesBuf(32);
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
    // 3 - Generate nonce using GenericHash
    byte[] nonce = new byte[AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES];
    SODIUM.cryptoGenericHash(
        nonce, nonce.length, payload, payload.length, randomKey, randomKey.length);

    // 4 - Pre-auth encoding
    byte[] preAuth = encode(header, nonce, footer);

    // 5 - XChaCha20Poly1305 encryption
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
            null, // No additional data
            nonce,
            key.toBytes());

    if (!success) {
      throw new PasetoException("Encryption failed");
    }

    // 6
    return concat(nonce, cipherText);
  }

  @Override
  public byte[] decrypt(
      LocalSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion) {
    byte[] nonce = segments.nonce();
    byte[] encryptedMessage = concat(segments.cipherText(), segments.tag());

    // 4
    byte[] preAuth = encode(header, nonce, footer);

    // 5 - XChaCha20Poly1305 decryption using Lazysodium
    byte[] message = new byte[encryptedMessage.length - AEAD.XCHACHA20POLY1305_IETF_ABYTES];
    long[] messageLen = new long[1];

    boolean success =
        SODIUM.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            message,
            messageLen,
            null, // No additional data
            encryptedMessage,
            encryptedMessage.length,
            preAuth,
            preAuth.length,
            nonce,
            key.toBytes());

    if (!success) {
      throw new PasetoException("Unable to decrypt the token");
    }

    return Arrays.copyOf(message, (int) messageLen[0]);
  }
}
