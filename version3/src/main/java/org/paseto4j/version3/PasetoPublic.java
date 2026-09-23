/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static org.paseto4j.commons.Version.V3;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.paseto4j.commons.Conditions;
import org.paseto4j.commons.PublicTokenPipeline;
import org.paseto4j.commons.SignatureScheme;

class PasetoPublic {

  private static final String CURVE_NAME = "secp384r1";

  private PasetoPublic() {}

  private static final SignatureScheme<ECPrivateKey, ECPublicKey> SCHEME =
      new SignatureScheme<>() {
        @Override
        public int signatureLength() {
          return 96;
        }

        @Override
        public byte[][] signingPreAuthPieces(
            ECPrivateKey privateKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          byte[] pk = publicKey(privateKey);
          Conditions.verify(pk.length == 49, "`pk` **MUST** be 49 bytes long");
          Conditions.verify(
              pk[0] == (byte) 0x02 || pk[0] == (byte) 0x03,
              "The first byte **MUST** be `0x02` or `0x03`");
          return new byte[][] {pk, header, message, footer, implicitAssertion};
        }

        @Override
        public byte[][] verificationPreAuthPieces(
            ECPublicKey publicKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {toCompressed(publicKey), header, message, footer, implicitAssertion};
        }

        @Override
        public byte[] sign(ECPrivateKey privateKey, byte[] preAuth) {
          byte[] signature = CryptoFunctions.sign(privateKey, preAuth);
          Conditions.verify(
              signature.length == 96, "The length of the signature **MUST** be 96 bytes long");
          return signature;
        }

        @Override
        public void verify(ECPublicKey publicKey, byte[] preAuth, byte[] signature)
            throws SignatureException {
          if (!CryptoFunctions.verify(publicKey, preAuth, signature)) {
            throw new SignatureException("Invalid signature");
          }
        }
      };

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign">...</a>
   */
  static String sign(
      ECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {
    return PublicTokenPipeline.sign(V3, SCHEME, privateKey, payload, footer, implicitAssertion);
  }

  /**
   * Parse the token, <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify">...</a>
   */
  static String parse(
      ECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    return PublicTokenPipeline.parse(V3, SCHEME, publicKey, signedMessage, footer, implicitAssertion);
  }

  public static byte[] publicKey(ECPrivateKey key) {
    return publicKeyFromPrivate(key.getS());
  }

  /** ECDSA Public Key Point Compression */
  private static byte[] publicKeyFromPrivate(BigInteger privKey) {
    X9ECParameters params = SECNamedCurves.getByName(CURVE_NAME);
    var curve =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    ECPoint point = curve.getG().multiply(privKey);
    return point.getEncoded(true);
  }

  private static byte[] toCompressed(ECPublicKey key) {
    X9ECParameters params = SECNamedCurves.getByName(CURVE_NAME);

    ECPoint bcPoint =
        params.getCurve().createPoint(key.getW().getAffineX(), key.getW().getAffineY());

    return bcPoint.getEncoded(true);
  }
}
