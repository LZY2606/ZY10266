/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V1;

import org.junit.jupiter.api.Test;

/** Contract of the segmented token parser and the immutable envelope it produces. */
class TokenParserTest {

  private static final String FOOTER = "{\"kid\":\"alice\"}";
  private static final String TOKEN =
      "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";
  private static final String TOKEN_FOOTER =
      "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}";

  @Test
  void parsesThreePartToken() {
    TokenEnvelope envelope = TokenParser.parse("v1.local.dfksjlf", V1, PURPOSE_LOCAL, null);

    assertEquals("v1.local.dfksjlf", envelope.toString());
    assertEquals("dfksjlf", envelope.payloadSegment());
    assertArrayEquals("v1.local.".getBytes(UTF_8), envelope.header());
    assertEquals(0, envelope.footer().length);
    assertEquals(new TokenAlgorithm(V1, PURPOSE_LOCAL), envelope.algorithm());
  }

  @Test
  void parsesFourPartTokenWithMatchingFooter() {
    TokenEnvelope envelope = TokenParser.parse(TOKEN, V1, PURPOSE_LOCAL, TOKEN_FOOTER);

    assertArrayEquals(TOKEN_FOOTER.getBytes(UTF_8), envelope.footer());
    assertEquals(TOKEN, envelope.toString());
  }

  @Test
  void payloadIsDecodedExactlyOnce() {
    TokenEnvelope envelope = TokenParser.parse("v1.local.aGVsbG8", V1, PURPOSE_LOCAL, null);

    assertArrayEquals("hello".getBytes(UTF_8), envelope.payload());
  }

  @Test
  void rejectsWrongHeader() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v2.local.dfksjlf", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsEmptyParts() {
    assertThrows(
        PasetoException.class, () -> TokenParser.parse("v1.local.", V1, PURPOSE_LOCAL, null));
    assertThrows(PasetoException.class, () -> TokenParser.parse("..", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsTooManySegments() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.aa.bb.cc", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsPaddedPayloadSegment() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.Zg==", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsNonBase64UrlPayloadSegment() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.dGVsbA**", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsUnexpectedFooterSegment() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.dfksjlf.Zm9v", V1, PURPOSE_LOCAL, null));
  }

  @Test
  void rejectsMissingFooterSegment() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.dfksjlf", V1, PURPOSE_LOCAL, FOOTER));
  }

  @Test
  void rejectsFooterMismatch() {
    assertThrows(
        PasetoException.class, () -> TokenParser.parse(TOKEN, V1, PURPOSE_LOCAL, "wrong"));
  }

  @Test
  void rejectsPaddedFooterSegment() {
    assertThrows(
        PasetoException.class,
        () -> TokenParser.parse("v1.local.dfksjlf.Zm9v==", V1, PURPOSE_LOCAL, "foo"));
  }

  @Test
  void envelopeIsImmutable() {
    TokenEnvelope envelope = TokenParser.parse(TOKEN, V1, PURPOSE_LOCAL, TOKEN_FOOTER);

    byte originalPayloadByte = envelope.payload()[0];
    byte[] payload = envelope.payload();
    byte[] footer = envelope.footer();
    payload[0] = (byte) (payload[0] + 1);
    footer[0] = (byte) (footer[0] + 1);

    assertEquals(originalPayloadByte, envelope.payload()[0]);
    assertArrayEquals(TOKEN_FOOTER.getBytes(UTF_8), envelope.footer());
  }
}
