/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Version adapter for the {@code local} purpose: declares the nonce/tag layout and the crypto
 * operations, while {@link LocalTokenPipeline} owns token parsing, segment decoding, PAE assembly,
 * authentication ordering and token construction.
 *
 * <p>All slices handed to the adapter have been length-validated by the pipeline. Implementations
 * must never return unauthenticated plaintext from {@link #decrypt}.
 */
public interface LocalCipher {

  /** Number of leading nonce bytes in the token payload. */
  int nonceLength();

  /**
   * Number of trailing authentication tag bytes in the token payload. A value of {@code 0} means
   * the cipher authenticates during encryption (AEAD): the pipeline then computes the pre-auth
   * encoding before encryption and passes it to {@link #encrypt} as additional data, and no
   * separate {@link #tag} stage runs.
   */
  int tagLength();

  /** Derive the nonce from the payload and the given randomness. */
  byte[] nonce(byte[] payload, byte[] random);

  /**
   * The pre-authentication pieces in version-specific order. {@code cipherText} is {@code null}
   * when the pieces are requested before encryption (AEAD additional data); versions that
   * authenticate the ciphertext must not reference it in that case.
   */
  byte[][] preAuthPieces(
      byte[] header, byte[] nonce, byte[] cipherText, byte[] footer, byte[] implicitAssertion);

  /**
   * Encrypt the payload. {@code preAuth} carries the PAE output for AEAD versions (additional
   * authenticated data) and is {@code null} otherwise. For AEAD versions the returned array
   * includes the authentication tag.
   */
  byte[] encrypt(SecretKey key, byte[] nonce, byte[] payload, byte[] preAuth);

  /** Compute the authentication tag over the pre-auth encoding. Only called when tagLength() > 0. */
  byte[] tag(SecretKey key, byte[] nonce, byte[] preAuth);

  /**
   * Verify the authentication tag (or the AEAD tag inside {@code cipherText}) and decrypt. Must
   * throw on authentication failure and never return unauthenticated plaintext.
   */
  byte[] decrypt(SecretKey key, byte[] nonce, byte[] cipherText, byte[] tag, byte[] preAuth);
}
