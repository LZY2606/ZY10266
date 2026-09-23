/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;

import java.util.Arrays;

/**
 * Shared stage pipeline for the {@code local} purpose: derives the nonce, assembles the PAE from
 * the pieces declared by the version adapter, runs encryption and authentication in the correct
 * order and builds the token. On decrypt it parses the token into a validated envelope, checks the
 * payload length before any slicing happens, and only then invokes the version crypto. The
 * unauthenticated plaintext never leaves the adapter before authentication succeeds.
 */
public final class LocalTokenPipeline {

  private LocalTokenPipeline() {}

  public static String encrypt(
      Version version,
      LocalCipher cipher,
      SecretKey key,
      byte[] random,
      String payload,
      String footer,
      String implicitAssertion) {
    requireNonNull(cipher);
    requireNonNull(key);
    requireNonNull(payload);

    TokenOut token = new TokenOut(version, PURPOSE_LOCAL);
    byte[] payloadBytes = payload.getBytes(UTF_8);
    byte[] footerBytes = bytes(footer);
    byte[] implicitBytes = bytes(implicitAssertion);

    byte[] nonce = cipher.nonce(payloadBytes, random);
    verify(
        nonce.length == cipher.nonceLength(),
        "Nonce should be " + cipher.nonceLength() + " bytes long");

    byte[] body;
    if (cipher.tagLength() == 0) {
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              cipher.preAuthPieces(token.header(), nonce, null, footerBytes, implicitBytes));
      body = cipher.encrypt(key, nonce, payloadBytes, preAuth);
    } else {
      byte[] cipherText = cipher.encrypt(key, nonce, payloadBytes, null);
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              cipher.preAuthPieces(token.header(), nonce, cipherText, footerBytes, implicitBytes));
      byte[] tag = cipher.tag(key, nonce, preAuth);
      verify(
          tag.length == cipher.tagLength(),
          "Tag should be " + cipher.tagLength() + " bytes long");
      body = ByteUtils.concat(cipherText, tag);
    }
    return token.payload(ByteUtils.concat(nonce, body)).footer(footer).doFinal();
  }

  public static String decrypt(
      Version version,
      LocalCipher cipher,
      SecretKey key,
      String token,
      String footer,
      String implicitAssertion) {
    requireNonNull(cipher);
    requireNonNull(key);
    requireNonNull(token);

    TokenEnvelope envelope = TokenParser.parse(token, version, PURPOSE_LOCAL, footer);
    byte[] ct = envelope.payload();

    int nonceLength = cipher.nonceLength();
    int tagLength = cipher.tagLength();
    verify(ct.length >= nonceLength + tagLength, "Token payload is too short");

    byte[] nonce = Arrays.copyOfRange(ct, 0, nonceLength);
    byte[] tag = Arrays.copyOfRange(ct, ct.length - tagLength, ct.length);
    byte[] cipherText = Arrays.copyOfRange(ct, nonceLength, ct.length - tagLength);

    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            cipher.preAuthPieces(
                envelope.header(),
                nonce,
                tagLength == 0 ? null : cipherText,
                bytes(footer),
                bytes(implicitAssertion)));

    byte[] message = cipher.decrypt(key, nonce, cipherText, tag, preAuth);
    try {
      return new String(message, UTF_8);
    } finally {
      ByteUtils.wipe(message);
    }
  }

  private static byte[] bytes(String value) {
    return value == null ? new byte[0] : value.getBytes(UTF_8);
  }
}
