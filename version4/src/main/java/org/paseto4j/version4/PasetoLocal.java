/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;

import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

public class PasetoLocal {
  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, CryptoFunctions.randomBytes(), payload, footer, implicit);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt">encrypt</a>
   */
  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(nonce.length == 32, "nonce should be 32 bytes");

    return LocalTokenPipeline.encrypt(new V4LocalScheme(key, nonce), payload, footer, implicitAssertion);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);

    return LocalTokenPipeline.decrypt(new V4LocalScheme(key), token, footer, implicitAssertion);
  }
}
