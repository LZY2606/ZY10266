/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/** Representation of a Paseto token */
public class Token {

  private final TokenEnvelope envelope;

  Token(String tokenString, TokenAlgorithm tokenAlgorithm, String footer) {
    this.envelope = TokenParser.parse(tokenString, tokenAlgorithm, footer);
  }

  public Token(String tokenString, Version version, Purpose purpose, String footer) {
    this(tokenString, new TokenAlgorithm(version, purpose), footer);
  }

  public String getPayload() {
    return envelope.payloadSegment();
  }

  public byte[] header() {
    return envelope.header();
  }

  @Override
  public String toString() {
    return envelope.token();
  }
}
