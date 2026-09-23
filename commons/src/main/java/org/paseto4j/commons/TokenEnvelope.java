/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Immutable, length-validated representation of a parsed PASETO token.
 *
 * <p>Instances are only created by {@link TokenParser} after the header, payload segment, footer
 * and their encoding have been validated. All byte arrays are defensively copied so callers can
 * never mutate the envelope.
 */
public final class TokenEnvelope {

  private final String token;
  private final TokenAlgorithm algorithm;
  private final String payloadSegment;
  private final byte[] payload;
  private final byte[] footer;

  TokenEnvelope(
      String token, TokenAlgorithm algorithm, String payloadSegment, byte[] payload, byte[] footer) {
    this.token = token;
    this.algorithm = algorithm;
    this.payloadSegment = payloadSegment;
    this.payload = payload.clone();
    this.footer = footer.clone();
  }

  /** The token header ({version}.{purpose}.) as bytes. */
  public byte[] header() {
    return algorithm.header().getBytes(UTF_8);
  }

  /** The algorithm the token was validated against. */
  public TokenAlgorithm algorithm() {
    return algorithm;
  }

  /** The raw base64url payload segment as it appeared in the token. */
  public String payloadSegment() {
    return payloadSegment;
  }

  /** A copy of the decoded payload segment. */
  public byte[] payload() {
    return payload.clone();
  }

  /** A copy of the decoded footer, empty when the token carries no footer. */
  public byte[] footer() {
    return footer.clone();
  }

  @Override
  public String toString() {
    return token;
  }
}
