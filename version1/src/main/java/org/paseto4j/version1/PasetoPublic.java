/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.paseto4j.commons.Version.V1;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.paseto4j.commons.PublicTokenPipeline;
import org.paseto4j.commons.SignatureScheme;

class PasetoPublic {

  private PasetoPublic() {}

  private static final SignatureScheme<RSAPrivateKey, RSAPublicKey> SCHEME =
      new SignatureScheme<>() {
        @Override
        public int signatureLength() {
          return 256;
        }

        @Override
        public byte[][] signingPreAuthPieces(
            RSAPrivateKey privateKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer};
        }

        @Override
        public byte[][] verificationPreAuthPieces(
            RSAPublicKey publicKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer};
        }

        @Override
        public byte[] sign(RSAPrivateKey privateKey, byte[] preAuth) {
          return CryptoFunctions.signRsaPssSha384(privateKey, preAuth);
        }

        @Override
        public void verify(RSAPublicKey publicKey, byte[] preAuth, byte[] signature)
            throws SignatureException {
          if (!CryptoFunctions.verifyRsaPssSha384(publicKey, preAuth, signature)) {
            throw new SignatureException("Invalid signature");
          }
        }
      };

  /**
   * Sign the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign">...</a>
   */
  static String sign(RSAPrivateKey privateKey, String payload, String footer) {
    return PublicTokenPipeline.sign(V1, SCHEME, privateKey, payload, footer, "");
  }

  /**
   * Parse the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify">...</a>
   */
  static String parse(RSAPublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    return PublicTokenPipeline.parse(V1, SCHEME, publicKey, signedMessage, footer, "");
  }
}
