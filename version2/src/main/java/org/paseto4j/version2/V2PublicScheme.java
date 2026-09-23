/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.PayloadLayout;
import org.paseto4j.commons.PublicScheme;
import org.paseto4j.commons.SignedSegments;
import org.paseto4j.commons.TokenAlgorithm;

/** Version 2 public scheme: Ed25519 detached signatures. */
class V2PublicScheme implements PublicScheme {

  private static final TokenAlgorithm ALGORITHM = new TokenAlgorithm(V2, PURPOSE_PUBLIC);
  private static final PayloadLayout LAYOUT = PayloadLayout.signed(64);

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private final PrivateKey privateKey;
  private final PublicKey publicKey;

  private V2PublicScheme(PrivateKey privateKey, PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static V2PublicScheme forSigning(PrivateKey privateKey) {
    return new V2PublicScheme(privateKey, null);
  }

  static V2PublicScheme forVerification(PublicKey publicKey) {
    return new V2PublicScheme(null, publicKey);
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
    byte[] m2 = encode(header, payload, footer);
    byte[] signature = new byte[64];
    byte[] sk = Arrays.copyOf(privateKey.toBytes(), 64);
    SODIUM.cryptoSignDetached(signature, m2, m2.length, sk);
    return signature;
  }

  @Override
  public void verify(SignedSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion)
      throws SignatureException {
    // 4
    byte[] m2 = encode(header, segments.message(), footer);

    // 5
    byte[] pk = Arrays.copyOf(publicKey.toBytes(), 32);
    boolean valid = SODIUM.cryptoSignVerifyDetached(segments.signature(), m2, m2.length, pk);
    if (!valid) {
      throw new SignatureException("Invalid signature");
    }
  }
}
