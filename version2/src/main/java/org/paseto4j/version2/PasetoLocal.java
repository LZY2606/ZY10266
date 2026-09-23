/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.util.Objects.requireNonNull;

import org.paseto4j.commons.LocalTokenPipeline;
import org.paseto4j.commons.SecretKey;

class PasetoLocal {

  private PasetoLocal() {}

  static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, V2LocalScheme.randomKey(), payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);

    return LocalTokenPipeline.encrypt(new V2LocalScheme(key, randomKey), payload, footer, "");
  }

  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);

    return LocalTokenPipeline.decrypt(new V2LocalScheme(key), token, footer, "");
  }
}
