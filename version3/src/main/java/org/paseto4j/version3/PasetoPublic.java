/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.util.Objects.requireNonNull;

import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.paseto4j.commons.PublicTokenPipeline;

class PasetoPublic {

  private PasetoPublic() {}

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign">...</a>
   */
  static String sign(
      ECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    return PublicTokenPipeline.sign(
        V3PublicScheme.forSigning(privateKey), payload, footer, implicitAssertion);
  }

  /**
   * Parse the token, <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify">...</a>
   */
  static String parse(
      ECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    return PublicTokenPipeline.parse(
        V3PublicScheme.forVerification(publicKey), signedMessage, footer, implicitAssertion);
  }

  public static byte[] publicKey(ECPrivateKey key) {
    return V3PublicScheme.publicKey(key);
  }
}
