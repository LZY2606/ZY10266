/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
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
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.PublicScheme;
import org.paseto4j.commons.SignedSegments;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 3 public scheme: ECDSA over secp384r1 with SHA-384. */
class V3PublicScheme implements PublicScheme {

  private static final String CURVE_NAME = "secp384r1";
  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V3, PURPOSE_PUBLIC);
  private static final PayloadLayout LAYOUT = PayloadLayout.signed(96);

  private final ECPrivateKey privateKey;
  private final ECPublicKey publicKey;

  private V3PublicScheme(ECPrivateKey privateKey, ECPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static V3PublicScheme forSigning(ECPrivateKey privateKey) {
    return new V3PublicScheme(privateKey, null);
  }

  static V3PublicScheme forVerification(ECPublicKey publicKey) {
    return new V3PublicScheme(null, publicKey);
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
    byte[] pk = publicKey(privateKey);
    Conditions.verify(pk.length == 49, "`pk` **MUST** be 49 bytes long");
    Conditions.verify(
        pk[0] == (byte) 0x02 || pk[0] == (byte) 0x03,
        "The first byte **MUST** be `0x02` or `0x03`");
    byte[] m2 = PreAuthenticationEncoder.encode(pk, header, payload, footer, implicitAssertion);

    // 4
    byte[] signature = CryptoFunctions.sign(privateKey, m2);
    Conditions.verify(signature.length == 96, "The length of the signature **MUST** be 96 bytes long");
    return signature;
  }

  @Override
  public void verify(SignedSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion)
      throws SignatureException {
    // 4
    byte[] pk = toCompressed(publicKey);
    byte[] m2 =
        PreAuthenticationEncoder.encode(pk, header, segments.message(), footer, implicitAssertion);

    // 5
    if (!CryptoFunctions.verify(publicKey, m2, segments.signature())) {
      throw new SignatureException("Invalid signature");
    }
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
