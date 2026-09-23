/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V4;

import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PublicScheme;
import org.paseto4j.commons.SignedSegments;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 4 public scheme: Ed25519 signatures. */
class V4PublicScheme implements PublicScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V4, PURPOSE_PUBLIC);
  private static final PayloadLayout LAYOUT = PayloadLayout.signed(64);

  private final EdECPrivateKey privateKey;
  private final EdECPublicKey publicKey;

  private V4PublicScheme(EdECPrivateKey privateKey, EdECPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static V4PublicScheme forSigning(EdECPrivateKey privateKey) {
    return new V4PublicScheme(privateKey, null);
  }

  static V4PublicScheme forVerification(EdECPublicKey publicKey) {
    return new V4PublicScheme(null, publicKey);
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
    // 3
    byte[] m2 = PreAuthenticationEncoder.encode(header, payload, footer, implicitAssertion);

    // 4
    return CryptoFunctions.sign(privateKey, m2);
  }

  @Override
  public void verify(SignedSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion)
      throws SignatureException {
    // 5
    byte[] m2 =
        PreAuthenticationEncoder.encode(header, segments.message(), footer, implicitAssertion);

    // 6
    if (!CryptoFunctions.verify(publicKey, m2, segments.signature())) {
      throw new SignatureException("Invalid signature");
    }
  }
}
