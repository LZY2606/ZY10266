/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

/**
 * Shared staging pipeline for local tokens: parse the token into an envelope, validate the
 * payload length against the version layout, delegate the version-specific cryptography to the
 * {@link LocalScheme} and assemble the resulting token.
 */
public final class LocalTokenPipeline {

  private LocalTokenPipeline() {}

  public static String encrypt(
      LocalScheme scheme, String payload, String footer, String implicitAssertion) {
    requireNonNull(scheme, "scheme");
    requireNonNull(payload, "payload");

    TokenAlgorithm algorithm = scheme.algorithm();
    byte[] body =
        scheme.encrypt(
            payload.getBytes(UTF_8),
            algorithm.header().getBytes(UTF_8),
            utf8(footer),
            utf8(implicitAssertion));

    return new TokenOut(algorithm.version(), algorithm.purpose())
        .payload(body)
        .footer(footer)
        .doFinal();
  }

  public static String decrypt(
      LocalScheme scheme, String token, String footer, String implicitAssertion) {
    requireNonNull(scheme, "scheme");
    requireNonNull(token, "token");

    TokenEnvelope envelope = TokenParser.parse(token, scheme.algorithm(), footer);
    LocalSegments segments = scheme.layout().splitLocal(envelope.payload());
    byte[] message =
        scheme.decrypt(segments, envelope.header(), envelope.footer(), utf8(implicitAssertion));
    return new String(message, UTF_8);
  }

  private static byte[] utf8(String value) {
    return value == null ? new byte[0] : value.getBytes(UTF_8);
  }
}
