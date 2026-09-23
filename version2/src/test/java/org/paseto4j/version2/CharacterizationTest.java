/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Base64;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.SecretKey;

/**
 * Characterization of the v2 token pipeline: valid tokens round-trip, short, truncated,
 * non-canonical and wrong-auth tokens are rejected with the expected exception category and never
 * with {@link IndexOutOfBoundsException}, and failure messages do not leak input secrets.
 */
class CharacterizationTest {

  private static final String KEY_HEX =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final SecretKey KEY = SecretKey.fromHexString(KEY_HEX);
  private static final String PAYLOAD = "{\"data\":\"this is a secret message\"}";
  private static final String FOOTER = "test-footer";

  private static String localToken;
  private static PrivateKey privateKey;
  private static PublicKey publicKey;
  private static String publicToken;

  @BeforeAll
  static void setUp() {
    localToken = Paseto.encrypt(KEY, PAYLOAD, FOOTER);

    byte[] seed = hexToBytes("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774");
    byte[] sk = new byte[64];
    byte[] pk = new byte[32];
    new LazySodiumJava(new SodiumJava()).cryptoSignSeedKeypair(pk, sk, seed);
    privateKey = PrivateKey.fromBytes(sk);
    publicKey = PublicKey.fromBytes(pk);
    publicToken = Paseto.sign(privateKey, PAYLOAD, FOOTER);
  }

  @Test
  void validLocalTokenDecrypts() {
    assertEquals(PAYLOAD, Paseto.decrypt(KEY, localToken, FOOTER));
  }

  @Test
  void validPublicTokenVerifies() throws SignatureException {
    assertEquals(PAYLOAD, Paseto.parse(publicKey, publicToken, FOOTER));
  }

  private static Stream<Arguments> invalidLocalTokens() {
    return Stream.of(
        Arguments.of("short", "v2.local.AA", PasetoException.class),
        Arguments.of("truncated", truncatePayload(localToken), PasetoException.class),
        Arguments.of("noncanonical", padPayload(localToken), PasetoException.class),
        Arguments.of("wrong-auth", corruptAuthTag(localToken), PasetoException.class));
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
        Arguments.of("short", "v2.public.AA", PasetoException.class),
        Arguments.of("truncated", truncatePayload(publicToken), SignatureException.class),
        Arguments.of("noncanonical", padPayload(publicToken), PasetoException.class),
        Arguments.of("wrong-auth", corruptAuthTag(publicToken), SignatureException.class));
  }

  @ParameterizedTest(name = "public {0} token is rejected")
  @MethodSource("invalidPublicTokens")
  void invalidPublicTokenIsRejected(
      String name, String token, Class<? extends Throwable> expected) {
    Throwable thrown = assertThrows(Throwable.class, () -> Paseto.parse(publicKey, token, FOOTER));
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
