/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.PublicTokenPipeline;
import org.paseto4j.commons.SignatureScheme;

class PasetoPublic {

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private PasetoPublic() {}

  private static final SignatureScheme<PrivateKey, PublicKey> SCHEME =
      new SignatureScheme<>() {
        @Override
        public int signatureLength() {
          return 64;
        }

        @Override
        public byte[][] signingPreAuthPieces(
            PrivateKey privateKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer};
        }

        @Override
        public byte[][] verificationPreAuthPieces(
            PublicKey publicKey,
            byte[] header,
            byte[] message,
            byte[] footer,
            byte[] implicitAssertion) {
          return new byte[][] {header, message, footer};
        }

        @Override
        public byte[] sign(PrivateKey privateKey, byte[] preAuth) {
          byte[] sk = Arrays.copyOf(privateKey.toBytes(), 64);
          try {
            byte[] signature = new byte[64];
            SODIUM.cryptoSignDetached(signature, preAuth, preAuth.length, sk);
            return signature;
          } finally {
            wipe(sk);
          }
        }

        @Override
        public void verify(PublicKey publicKey, byte[] preAuth, byte[] signature)
            throws SignatureException {
          byte[] pk = Arrays.copyOf(publicKey.toBytes(), 32);
          boolean valid = SODIUM.cryptoSignVerifyDetached(signature, preAuth, preAuth.length, pk);
          if (!valid) {
            throw new SignatureException("Invalid signature");
          }
        }
      };

  static String sign(PrivateKey privateKey, String payload, String footer) {
    return PublicTokenPipeline.sign(V2, SCHEME, privateKey, payload, footer, "");
  }

  static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    return PublicTokenPipeline.parse(V2, SCHEME, publicKey, signedMessage, footer, "");
  }
}
