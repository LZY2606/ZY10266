/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.util.Objects.requireNonNull;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.paseto4j.commons.PublicTokenPipeline;

class PasetoPublic {

  private PasetoPublic() {}

  /**
   * Sign the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign">...</a>
   */
  static String sign(RSAPrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    return PublicTokenPipeline.sign(V1PublicScheme.forSigning(privateKey), payload, footer, "");
  }

  /**
   * Parse the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify">...</a>
   */
  static String parse(RSAPublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    return PublicTokenPipeline.parse(
        V1PublicScheme.forVerification(publicKey), signedMessage, footer, "");
  }
}
