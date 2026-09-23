/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.security.SignatureException;

/**
 * Version adapter for the {@code public} purpose: declares the signature layout and the crypto
 * operations, while {@link PublicTokenPipeline} owns token parsing, segment decoding, PAE assembly
 * and token construction.
 *
 * @param <PrivT> private key type used for signing
 * @param <PubT> public key type used for verification
 */
public interface SignatureScheme<PrivT, PubT> {

  /** Number of trailing signature bytes in the token payload. */
  int signatureLength();

  /** The pre-authentication pieces for signing, in version-specific order. */
  byte[][] signingPreAuthPieces(
      PrivT privateKey, byte[] header, byte[] message, byte[] footer, byte[] implicitAssertion);

  /** The pre-authentication pieces for verification, in version-specific order. */
  byte[][] verificationPreAuthPieces(
      PubT publicKey, byte[] header, byte[] message, byte[] footer, byte[] implicitAssertion);

  /** Sign the pre-auth encoding. */
  byte[] sign(PrivT privateKey, byte[] preAuth);

  /** Verify the signature over the pre-auth encoding, throwing on failure. */
  void verify(PubT publicKey, byte[] preAuth, byte[] signature) throws SignatureException;
}
