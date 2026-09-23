/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.util.Objects.requireNonNull;

import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import org.paseto4j.commons.PublicTokenPipeline;

public class PasetoPublic {
  private PasetoPublic() {}

  static String sign(
      EdECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    return PublicTokenPipeline.sign(
        V4PublicScheme.forSigning(privateKey), payload, footer, implicitAssertion);
  }

  public static String parse(
      EdECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    return PublicTokenPipeline.parse(
        V4PublicScheme.forVerification(publicKey), signedMessage, footer, implicitAssertion);
  }
}
