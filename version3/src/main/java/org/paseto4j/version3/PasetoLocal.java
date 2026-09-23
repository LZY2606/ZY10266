/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.util.Objects.requireNonNull;
import static org.paseto4j.version3.CryptoFunctions.randomBytes;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, randomBytes(32), payload, footer, implicit);
  }

  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicit) {
    requireNonNull(key);
    requireNonNull(payload);

    return LocalTokenPipeline.encrypt(new V3LocalScheme(key, nonce), payload, footer, implicit);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token) {
    return decrypt(key, token, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);

    return LocalTokenPipeline.decrypt(new V3LocalScheme(key), token, footer, implicitAssertion);
  }
}
