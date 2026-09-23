/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PayloadLayoutTest {

  @Test
  void splitsLocalPayloadIntoNonceCipherTextAndTag() {
    byte[] payload = new byte[32 + 10 + 48];
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) i;
    }

    LocalSegments segments = PayloadLayout.local(32, 48).splitLocal(payload);

    assertEquals(32, segments.nonce().length);
    assertEquals(10, segments.cipherText().length);
    assertEquals(48, segments.tag().length);
    assertEquals(0, segments.nonce()[0]);
    assertEquals(32, segments.cipherText()[0]);
    assertEquals(42, segments.tag()[0]);
  }

  @Test
  void localPayloadShorterThanNoncePlusTagIsRejected() {
    PayloadLayout layout = PayloadLayout.local(32, 48);

    assertThrows(PasetoException.class, () -> layout.splitLocal(new byte[79]));
    assertThrows(PasetoException.class, () -> layout.splitLocal(new byte[0]));
  }

  @Test
  void localPayloadOfExactlyNoncePlusTagHasEmptyCipherText() {
    LocalSegments segments =
        assertDoesNotThrow(() -> PayloadLayout.local(32, 48).splitLocal(new byte[80]));

    assertEquals(0, segments.cipherText().length);
  }

  @Test
  void splitsSignedPayloadIntoMessageAndSignature() {
    byte[] payload = new byte[20 + 64];
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) i;
    }

    SignedSegments segments = PayloadLayout.signed(64).splitSigned(payload);

    assertEquals(20, segments.message().length);
    assertEquals(64, segments.signature().length);
    assertEquals(0, segments.message()[0]);
    assertEquals(20, segments.signature()[0]);
  }

  @Test
  void signedPayloadShorterThanSignatureIsRejected() {
    PayloadLayout layout = PayloadLayout.signed(64);

    assertThrows(PasetoException.class, () -> layout.splitSigned(new byte[63]));
  }

  @Test
  void signedPayloadOfExactlySignatureLengthHasEmptyMessage() {
    SignedSegments segments =
        assertDoesNotThrow(() -> PayloadLayout.signed(64).splitSigned(new byte[64]));

    assertEquals(0, segments.message().length);
  }

  @Test
  void segmentsAreDefensivelyCopied() {
    byte[] payload = new byte[80];
    LocalSegments segments = PayloadLayout.local(32, 48).splitLocal(payload);

    payload[0] = 1;
    segments.nonce()[1] = 1;

    assertEquals(0, segments.nonce()[0]);
    assertEquals(0, segments.nonce()[1]);
  }

  @Test
  void tooShortMessageDoesNotLeakInput() {
    PasetoException exception =
        assertThrows(
            PasetoException.class, () -> PayloadLayout.local(32, 48).splitLocal(new byte[10]));

    assertEquals(
        "Token payload is too short: expected at least 80 bytes but got 10",
        exception.getMessage());
  }
}
