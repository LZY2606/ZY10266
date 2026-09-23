/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.util.Objects.requireNonNull;
import static org.paseto4j.version1.CryptoFunctions.randomBytes;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, randomBytes(), payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);

    return LocalTokenPipeline.encrypt(new V1LocalScheme(key, randomKey), payload, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt">...</a>
   */
  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);

    return LocalTokenPipeline.decrypt(new V1LocalScheme(key), token, footer, "");
  }
}
