/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.util.Objects.requireNonNull;

import java.security.SignatureException;
import org.paseto4j.commons.PublicTokenPipeline;

class PasetoPublic {

  private PasetoPublic() {}

  static String sign(PrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    return PublicTokenPipeline.sign(V2PublicScheme.forSigning(privateKey), payload, footer, "");
  }

  static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    return PublicTokenPipeline.parse(
        V2PublicScheme.forVerification(publicKey), signedMessage, footer, "");
  }
}
