/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;

import java.security.SignatureException;

/**
 * Shared staging pipeline for public tokens: parse the token into an envelope, validate the
 * payload length against the version signature layout, delegate signing/verification to the
 * {@link PublicScheme} and assemble the resulting token.
 */
public final class PublicTokenPipeline {

  private PublicTokenPipeline() {}

  public static String sign(
      PublicScheme scheme, String payload, String footer, String implicitAssertion) {
    requireNonNull(scheme, "scheme");
    requireNonNull(payload, "payload");

    TokenAlgorithm algorithm = scheme.algorithm();
    byte[] payloadBytes = payload.getBytes(UTF_8);
    byte[] signature =
        scheme.sign(
            payloadBytes,
            algorithm.header().getBytes(UTF_8),
            utf8(footer),
            utf8(implicitAssertion));

    return new TokenOut(algorithm.version(), algorithm.purpose())
        .payload(concat(payloadBytes, signature))
        .footer(footer)
        .doFinal();
  }

  public static String parse(
      PublicScheme scheme, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(scheme, "scheme");
    requireNonNull(signedMessage, "signedMessage");

    TokenEnvelope envelope = TokenParser.parse(signedMessage, scheme.algorithm(), footer);
    SignedSegments segments = scheme.layout().splitSigned(envelope.payload());
    scheme.verify(segments, envelope.header(), envelope.footer(), utf8(implicitAssertion));
    return new String(segments.message(), UTF_8);
  }

  private static byte[] utf8(String value) {
    return value == null ? new byte[0] : value.getBytes(UTF_8);
  }
}
