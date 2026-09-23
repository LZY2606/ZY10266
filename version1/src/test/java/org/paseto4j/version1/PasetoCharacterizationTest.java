/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;

/**
 * Characterization of the token pipeline for v1: valid, short, truncated, non-canonical and
 * wrong-authentication inputs must keep failing with the documented exception categories.
 */
class PasetoCharacterizationTest {

  private static final String KEY_HEX =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final SecretKey KEY = SecretKey.fromHexString(KEY_HEX);
  private static final String PAYLOAD = "{\"data\":\"top-secret-characterization-payload\"}";
  private static final String FOOTER = "characterization-footer";
  private static final String LOCAL_HEADER = "v1.local.";
  private static final String PUBLIC_HEADER = "v1.public.";

  private static KeyPair keyPair;

  @BeforeAll
  static void generateKeys() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    keyPair = generator.generateKeyPair();
  }

  private static Stream<Arguments> localCases() {
    return Stream.of(
        Arguments.of("valid", (Function<String, String>) token -> token, null),
        Arguments.of(
            "short", (Function<String, String>) token -> LOCAL_HEADER + "AQ", PasetoException.class),
        Arguments.of(
            "truncated",
            (Function<String, String>) token -> token.substring(0, LOCAL_HEADER.length() + 8),
            PasetoException.class),
        Arguments.of(
            "noncanonical",
            (Function<String, String>) token -> LOCAL_HEADER + "!" + token.substring(LOCAL_HEADER.length()),
            PasetoException.class),
        Arguments.of(
            "wrong-auth",
            (Function<String, String>) PasetoCharacterizationTest::flipPayloadChar,
            IllegalStateException.class));
  }

  @ParameterizedTest(name = "local {0}")
  @MethodSource("localCases")
  void localCharacterization(
      String name, Function<String, String> tamper, Class<? extends Exception> expected) {
    String candidate = tamper.apply(Paseto.encrypt(KEY, PAYLOAD, FOOTER));

    if (expected == null) {
      assertEquals(PAYLOAD, Paseto.decrypt(KEY, candidate, FOOTER));
    } else {
      Exception e = assertThrows(expected, () -> Paseto.decrypt(KEY, candidate, FOOTER));
      assertDoesNotLeakSecret(e);
    }
  }

  private static Stream<Arguments> publicCases() {
    return Stream.of(
        Arguments.of("valid", (Function<String, String>) token -> token, null),
        Arguments.of(
            "short", (Function<String, String>) token -> PUBLIC_HEADER + "AQ", PasetoException.class),
        Arguments.of(
            "truncated",
            (Function<String, String>) token -> token.substring(0, PUBLIC_HEADER.length() + 8),
            PasetoException.class),
        Arguments.of(
            "noncanonical",
            (Function<String, String>) token -> PUBLIC_HEADER + "!" + token.substring(PUBLIC_HEADER.length()),
            PasetoException.class),
        Arguments.of(
            "wrong-auth",
            (Function<String, String>) PasetoCharacterizationTest::flipPayloadChar,
            SignatureException.class));
  }

  @ParameterizedTest(name = "public {0}")
  @MethodSource("publicCases")
  void publicCharacterization(
      String name, Function<String, String> tamper, Class<? extends Exception> expected)
      throws SignatureException {
    String candidate =
        tamper.apply(Paseto.sign((RSAPrivateKey) keyPair.getPrivate(), PAYLOAD, FOOTER));

    if (expected == null) {
      assertEquals(PAYLOAD, Paseto.parse((RSAPublicKey) keyPair.getPublic(), candidate, FOOTER));
    } else {
      Exception e =
          assertThrows(
              expected, () -> Paseto.parse((RSAPublicKey) keyPair.getPublic(), candidate, FOOTER));
      assertDoesNotLeakSecret(e);
    }
  }

  private static String flipPayloadChar(String token) {
    int payloadStart = token.indexOf('.', token.indexOf('.') + 1) + 1;
    int lastDot = token.lastIndexOf('.');
    int payloadEnd = lastDot >= payloadStart ? lastDot : token.length();
    int middle = (payloadStart + payloadEnd) / 2;
    char current = token.charAt(middle);
    char flipped = current == 'A' ? 'B' : 'A';
    return token.substring(0, middle) + flipped + token.substring(middle + 1);
  }

  private static void assertDoesNotLeakSecret(Exception e) {
    String message = e.getMessage();
    if (message != null) {
      assertFalse(message.contains("top-secret"), "failure message leaks the payload");
      assertFalse(message.contains(KEY_HEX), "failure message leaks the key");
    }
  }
}
