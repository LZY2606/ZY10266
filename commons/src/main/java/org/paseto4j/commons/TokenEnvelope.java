/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Immutable representation of a parsed PASETO token. All segments have been validated and decoded
 * by {@link TokenParser}; byte arrays are defensively copied on construction and access.
 */
public final class TokenEnvelope {

  private final TokenAlgorithm algorithm;
  private final String token;
  private final String payloadSegment;
  private final byte[] payload;
  private final byte[] footer;

  TokenEnvelope(
      TokenAlgorithm algorithm,
      String token,
      String payloadSegment,
      byte[] payload,
      byte[] footer) {
    this.algorithm = algorithm;
    this.token = token;
    this.payloadSegment = payloadSegment;
    this.payload = payload.clone();
    this.footer = footer.clone();
  }

  public TokenAlgorithm algorithm() {
    return algorithm;
  }

  /** The token header ({version}.{purpose}.) as bytes, suitable for pre-authentication encoding. */
  public byte[] header() {
    return algorithm.header().getBytes(UTF_8);
  }

  /** The raw, still encoded, payload segment of the token. */
  public String payloadSegment() {
    return payloadSegment;
  }

  /** The decoded payload bytes of the token. */
  public byte[] payload() {
    return payload.clone();
  }

  /** The decoded footer bytes, empty when the token carries no footer. */
  public byte[] footer() {
    return footer.clone();
  }

  /** The original token string. */
  public String token() {
    return token;
  }
}
