/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.paseto4j.commons.Version.V4;

import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import org.paseto4j.commons.PublicTokenPipeline;
import org.paseto4j.commons.SignatureScheme;

public class PasetoPublic {
  private PasetoPublic() {}

  private static final SignatureScheme<EdECPrivateKey, EdECPublicKey> SCHEME =
      new SignatureScheme<>() {
        @Override
        public int signatureLength() {
          return 64;
        }

        @Override
        public byte[][] signingPreAuthPieces(
            EdECPrivateKey privateKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer, implicitAssertion};
        }

        @Override
        public byte[][] verificationPreAuthPieces(
            EdECPublicKey publicKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer, implicitAssertion};
        }

        @Override
        public byte[] sign(EdECPrivateKey privateKey, byte[] preAuth) {
          return CryptoFunctions.sign(privateKey, preAuth);
        }

        @Override
        public void verify(EdECPublicKey publicKey, byte[] preAuth, byte[] signature)
            throws SignatureException {
          if (!CryptoFunctions.verify(publicKey, preAuth, signature)) {
            throw new SignatureException("Invalid signature");
          }
        }
      };

  static String sign(
      EdECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    return PublicTokenPipeline.sign(V4, SCHEME, privateKey, payload, footer, implicitAssertion);
  }

  public static String parse(
      EdECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    return PublicTokenPipeline.parse(V4, SCHEME, publicKey, signedMessage, footer, implicitAssertion);
  }
}
