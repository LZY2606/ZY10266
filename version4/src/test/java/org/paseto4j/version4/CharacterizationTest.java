/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;

/**
 * Characterization of the v4 token pipeline: valid tokens round-trip, short, truncated,
 * non-canonical and wrong-auth tokens are rejected with the expected exception category and never
 * with {@link IndexOutOfBoundsException}, and failure messages do not leak input secrets.
 */
class CharacterizationTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String KEY_HEX =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final SecretKey KEY = SecretKey.fromHexString(KEY_HEX);
  private static final String PAYLOAD = "{\"data\":\"this is a secret message\"}";
  private static final String FOOTER = "test-footer";

  private static String localToken;
  private static KeyPair keyPair;
  private static String publicToken;

  @BeforeAll
  static void setUp() throws Exception {
    localToken = Paseto.encrypt(KEY, PAYLOAD, FOOTER);

    KeyPairGenerator generator =
        KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
    keyPair = generator.generateKeyPair();
    publicToken = Paseto.sign((EdECPrivateKey) keyPair.getPrivate(), PAYLOAD, FOOTER);
  }

  @Test
  void validLocalTokenDecrypts() {
    assertEquals(PAYLOAD, Paseto.decrypt(KEY, localToken, FOOTER));
  }

  @Test
  void validPublicTokenVerifies() throws SignatureException {
    assertEquals(PAYLOAD, Paseto.parse((EdECPublicKey) keyPair.getPublic(), publicToken, FOOTER));
  }

  private static Stream<Arguments> invalidLocalTokens() {
    return Stream.of(
        Arguments.of("short", "v4.local.AA", PasetoException.class),
        Arguments.of("truncated", truncatePayload(localToken), IllegalStateException.class),
        Arguments.of("noncanonical", padPayload(localToken), PasetoException.class),
        Arguments.of("wrong-auth", corruptAuthTag(localToken), IllegalStateException.class));
  }

  @ParameterizedTest(name = "local {0} token is rejected")
  @MethodSource("invalidLocalTokens")
  void invalidLocalTokenIsRejected(
      String name, String token, Class<? extends Throwable> expected) {
    Throwable thrown = assertThrows(Throwable.class, () -> Paseto.decrypt(KEY, token, FOOTER));
    assertEquals(expected, thrown.getClass(), name);
    assertDoesNotLeakSecrets(thrown);
  }

  private static Stream<Arguments> invalidPublicTokens() {
    return Stream.of(
        Arguments.of("short", "v4.public.AA", PasetoException.class),
        Arguments.of("truncated", truncatePayload(publicToken), SignatureException.class),
        Arguments.of("noncanonical", padPayload(publicToken), PasetoException.class),
        Arguments.of("wrong-auth", corruptAuthTag(publicToken), SignatureException.class));
  }

  @ParameterizedTest(name = "public {0} token is rejected")
  @MethodSource("invalidPublicTokens")
  void invalidPublicTokenIsRejected(
      String name, String token, Class<? extends Throwable> expected) {
    Throwable thrown =
        assertThrows(
            Throwable.class,
            () -> Paseto.parse((EdECPublicKey) keyPair.getPublic(), token, FOOTER));
    assertEquals(expected, thrown.getClass(), name);
    assertDoesNotLeakSecrets(thrown);
  }

  private static void assertDoesNotLeakSecrets(Throwable thrown) {
    String message = thrown.getMessage();
    if (message != null) {
      assertFalse(message.contains("secret message"), "failure message leaks the payload");
      assertFalse(message.contains(KEY_HEX.substring(0, 16)), "failure message leaks the key");
    }
  }

  private static String mapPayloadSegment(String token, UnaryOperator<String> mapper) {
    String[] parts = token.split("\\.", -1);
    parts[2] = mapper.apply(parts[2]);
    return String.join(".", parts);
  }

  private static String truncatePayload(String token) {
    return mapPayloadSegment(token, segment -> segment.substring(0, segment.length() - 4));
  }

  private static String padPayload(String token) {
    return mapPayloadSegment(token, segment -> segment + "=");
  }

  private static String corruptAuthTag(String token) {
    return mapPayloadSegment(
        token,
        segment -> {
          byte[] decoded = Base64.getUrlDecoder().decode(segment);
          decoded[decoded.length - 1] ^= 0x01;
          return Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
        });
  }
}
