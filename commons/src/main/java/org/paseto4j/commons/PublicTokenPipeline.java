/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;

import java.security.SignatureException;
import java.util.Arrays;

/**
 * Shared stage pipeline for the {@code public} purpose: assembles the PAE from the pieces declared
 * by the version adapter, runs the signature operation and builds the token. On parse it validates
 * the token into an envelope and checks the payload length before any slicing happens, so version
 * implementations never see out-of-bounds input.
 */
public final class PublicTokenPipeline {

  private PublicTokenPipeline() {}

  public static <PrivT> String sign(
      Version version,
      SignatureScheme<PrivT, ?> scheme,
      PrivT privateKey,
      String payload,
      String footer,
      String implicitAssertion) {
    requireNonNull(scheme);
    requireNonNull(privateKey);
    requireNonNull(payload);

    TokenOut token = new TokenOut(version, PURPOSE_PUBLIC);
    byte[] message = payload.getBytes(UTF_8);

    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            scheme.signingPreAuthPieces(
                privateKey, token.header(), message, bytes(footer), bytes(implicitAssertion)));
    byte[] signature = scheme.sign(privateKey, preAuth);
    verify(
        signature.length == scheme.signatureLength(),
        "The length of the signature **MUST** be " + scheme.signatureLength() + " bytes long");

    return token.payload(ByteUtils.concat(message, signature)).footer(footer).doFinal();
  }

  public static <PubT> String parse(
      Version version,
      SignatureScheme<?, PubT> scheme,
      PubT publicKey,
      String signedMessage,
      String footer,
      String implicitAssertion)
      throws SignatureException {
    requireNonNull(scheme);
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    TokenEnvelope envelope = TokenParser.parse(signedMessage, version, PURPOSE_PUBLIC, footer);
    byte[] sm = envelope.payload();

    verify(sm.length >= scheme.signatureLength(), "Token payload is too short");
    byte[] signature = Arrays.copyOfRange(sm, sm.length - scheme.signatureLength(), sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - scheme.signatureLength());

    byte[] preAuth =
        PreAuthenticationEncoder.encode(
            scheme.verificationPreAuthPieces(
                publicKey, envelope.header(), message, bytes(footer), bytes(implicitAssertion)));
    scheme.verify(publicKey, preAuth, signature);

    return new String(message, UTF_8);
  }

  private static byte[] bytes(String value) {
    return value == null ? new byte[0] : value.getBytes(UTF_8);
  }
}
