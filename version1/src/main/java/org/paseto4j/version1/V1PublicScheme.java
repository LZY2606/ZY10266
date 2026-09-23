/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PublicScheme;
import org.paseto4j.commons.SignedSegments;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 1 public scheme: RSA-PSS with SHA-384. */
class V1PublicScheme implements PublicScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V1, PURPOSE_PUBLIC);
  private static final PayloadLayout LAYOUT = PayloadLayout.signed(256);

  private final RSAPrivateKey privateKey;
  private final RSAPublicKey publicKey;

  private V1PublicScheme(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static V1PublicScheme forSigning(RSAPrivateKey privateKey) {
    return new V1PublicScheme(privateKey, null);
  }

  static V1PublicScheme forVerification(RSAPublicKey publicKey) {
    return new V1PublicScheme(null, publicKey);
  }

  @Override
  public TokenAlgorithm algorithm() {
    return ALGORITHM;
  }

  @Override
  public PayloadLayout layout() {
    return LAYOUT;
  }

  @Override
  public byte[] sign(byte[] payload, byte[] header, byte[] footer, byte[] implicitAssertion) {
    // 2
    byte[] m2 = encode(header, payload, footer);

    // 3
    return CryptoFunctions.signRsaPssSha384(privateKey, m2);
  }

  @Override
  public void verify(SignedSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion)
      throws SignatureException {
    // 4
    byte[] m2 = encode(header, segments.message(), footer);

    // 5
    if (!CryptoFunctions.verifyRsaPssSha384(publicKey, m2, segments.signature())) {
      throw new SignatureException("Invalid signature");
    }
  }
}
