/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class TokenParserTest {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V1, PURPOSE_LOCAL);

  private static String encode(String value) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(UTF_8));
  }

  @Test
  void parsesTokenWithoutFooter() {
    TokenEnvelope envelope =
        TokenParser.parse("v1.local." + encode("payload"), ALGORITHM, null);

    assertEquals(ALGORITHM, envelope.algorithm());
    assertEquals("v1.local.", new String(envelope.header(), UTF_8));
    assertEquals(encode("payload"), envelope.payloadSegment());
    assertArrayEquals("payload".getBytes(UTF_8), envelope.payload());
    assertArrayEquals(new byte[0], envelope.footer());
    assertEquals("v1.local." + encode("payload"), envelope.token());
  }

  @Test
  void parsesTokenWithMatchingFooter() {
    String token = "v1.local." + encode("payload") + "." + encode("footer");

    TokenEnvelope envelope = TokenParser.parse(token, ALGORITHM, "footer");

    assertArrayEquals("footer".getBytes(UTF_8), envelope.footer());
  }

  @Test
  void wrongHeaderIsRejected() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.public." + encode("payload"), ALGORITHM, null));
    assertThrows(
        PasetoException.class,
        () ->
            TokenParser.parse(
                "v1.local." + encode("payload"), new TokenAlgorithm(V1, PURPOSE_PUBLIC), null));
  }

  @Test
  void missingPartsAreRejected() {
    assertThrows(PasetoException.class, () -> TokenParser.parse("v1.local.", ALGORITHM, null));
    assertThrows(PasetoException.class, () -> TokenParser.parse("v1.local", ALGORITHM, null));
    assertThrows(PasetoException.class, () -> TokenParser.parse("..", ALGORITHM, null));
  }

  @Test
  void unexpectedFooterSegmentIsRejected() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local." + encode("payload") + "." + encode("f"), ALGORITHM, null));
  }

  @Test
  void missingFooterSegmentIsRejected() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local." + encode("payload"), ALGORITHM, "footer"));
  }

  @Test
  void nonCanonicalPayloadEncodingIsRejected() {
    assertThrows(
        PasetoException.class, () -> TokenParser.parse("v1.local.!!!", ALGORITHM, null));
    assertThrows(
        PasetoException.class, () -> TokenParser.parse("v1.local.ab+cd/ef", ALGORITHM, null));
  }

  @Test
  void nonCanonicalFooterEncodingIsRejected() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local." + encode("payload") + ".!!!", ALGORITHM, "footer"));
  }

  @Test
  void footerMismatchIsRejected() {
    String token = "v1.local." + encode("payload") + "." + encode("footer");

    assertThrows(PasetoException.class, () -> TokenParser.parse(token, ALGORITHM, "wrong"));
  }

  @Test
  void nullTokenIsRejected() {
    assertThrows(PasetoException.class, () -> TokenParser.parse(null, ALGORITHM, null));
  }

  @Test
  void envelopeIsImmutable() {
    TokenEnvelope envelope = TokenParser.parse("v1.local." + encode("payload"), ALGORITHM, null);

    byte[] payload = envelope.payload();
    payload[0] = 'X';
    byte[] footer = envelope.footer();

    assertArrayEquals("payload".getBytes(UTF_8), envelope.payload());
    assertArrayEquals(new byte[0], footer);
  }

  @Test
  void tokenDelegatesToParser() {
    String token = "v1.local." + encode("payload") + "." + encode("footer");

    Token parsed = assertDoesNotThrow(() -> new Token(token, V1, PURPOSE_LOCAL, "footer"));

    assertEquals(encode("payload"), parsed.getPayload());
    assertArrayEquals("v1.local.".getBytes(UTF_8), parsed.header());
    assertEquals(token, parsed.toString());
  }
}
