/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.paseto4j.commons.Conditions.isNullOrEmpty;
import static org.paseto4j.commons.Conditions.verify;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;

/**
 * Segmented token parser: splits a token into header, payload segment and footer, enforces the
 * base64url (unpadded) encoding rules and produces an immutable {@link TokenEnvelope}. All
 * decoding happens here so that downstream code only slices length-validated byte arrays.
 */
public final class TokenParser {

  private TokenParser() {}

  public static TokenEnvelope parse(
      String token, Version version, Purpose purpose, String expectedFooter) {
    return parse(token, new TokenAlgorithm(version, purpose), expectedFooter);
  }

  public static TokenEnvelope parse(
      String token, TokenAlgorithm tokenAlgorithm, String expectedFooter) {
    verify(token != null, "Token must not be null");
    verify(
        token.startsWith(tokenAlgorithm.header()),
        "Token should start with " + tokenAlgorithm.header());

    String[] tokenParts = token.split("\\.", -1);
    if (isNullOrEmpty(expectedFooter)) {
      verify(tokenParts.length == 3, "Token should consists of exactly 3 parts");
    } else {
      verify(
          tokenParts.length == 4,
          "An non-empty footer has been passed, so the token should consist of exactly 4 parts");
    }

    for (int i = 0; i < 3; i++) {
      verify(
          !isNullOrEmpty(tokenParts[i]),
          format(Locale.ROOT, "Token part %d cannot be null or empty", i));
    }

    byte[] payload = decodeSegment(tokenParts[2], "payload");
    byte[] footer = new byte[0];
    if (tokenParts.length == 4) {
      footer = decodeSegment(tokenParts[3], "footer");
      verify(
          MessageDigest.isEqual(footer, expectedFooter.getBytes(UTF_8)), "footer does not match");
    }
    return new TokenEnvelope(token, tokenAlgorithm, tokenParts[2], payload, footer);
  }

  private static byte[] decodeSegment(String segment, String name) {
    verify(
        segment.indexOf('=') < 0,
        format(Locale.ROOT, "Token %s must be base64url encoded without padding", name));
    try {
      return Base64.getUrlDecoder().decode(segment);
    } catch (IllegalArgumentException e) {
      throw new PasetoException(
          format(Locale.ROOT, "Token %s is not valid base64url", name));
    }
  }
}
