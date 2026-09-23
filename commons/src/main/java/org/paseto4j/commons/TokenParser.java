/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

import java.security.MessageDigest;
import java.util.Locale;

/**
 * Splits a PASETO token into its segments and validates the header, segment count, non-empty
 * parts, base64url encoding and the optional footer. The result is an immutable {@link
 * TokenEnvelope}; no cryptographic verification happens here.
 */
public final class TokenParser {

  private TokenParser() {}

  public static TokenEnvelope parse(String token, TokenAlgorithm algorithm, String expectedFooter) {
    verify(
        token != null && token.startsWith(algorithm.header()),
        "Token should start with " + algorithm.header());

    String[] tokenParts = token.split("\\.", -1);
    if (isNullOrEmpty(expectedFooter)) {
      verify(
          tokenParts.length != 4,
          "An non-empty footer has been passed, so the token should consist of exactly 4 parts");
    } else {
      verify(tokenParts.length != 3, "Token should consists of exactly 3 parts");
    }
    verify(tokenParts.length >= 3, "Token should consist of at least 3 parts");

    for (int i = 0; i < 3; i++) {
      verify(
          !isNullOrEmpty(tokenParts[i]),
          format(Locale.ROOT, "Token part %d cannot be null or empty", i));
    }

    byte[] payload = decodeSegment(tokenParts[2], "payload");
    byte[] footer = new byte[0];
    if (!isNullOrEmpty(expectedFooter)) {
      footer = decodeSegment(tokenParts[3], "footer");
      verify(
          MessageDigest.isEqual(footer, expectedFooter.getBytes(UTF_8)), "footer does not match");
    }
    return new TokenEnvelope(algorithm, token, tokenParts[2], payload, footer);
  }

  public static TokenEnvelope parse(
      String token, Version version, Purpose purpose, String expectedFooter) {
    return parse(token, new TokenAlgorithm(version, purpose), expectedFooter);
  }

  private static byte[] decodeSegment(String segment, String name) {
    try {
      return getUrlDecoder().decode(segment);
    } catch (IllegalArgumentException e) {
      throw new PasetoException("Token " + name + " is not valid base64url");
    }
  }
}
