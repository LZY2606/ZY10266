/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Version-specific cryptographic operations for local (symmetric) tokens. Implementations live in
 * the version modules and declare their nonce/tag layout; the shared staging (token parsing,
 * segment decoding, length validation, token assembly) is handled by {@link LocalTokenPipeline}.
 */
public interface LocalScheme {

  TokenAlgorithm algorithm();

  /** The nonce/tag layout of the decoded token payload. */
  PayloadLayout layout();

  /**
   * Encrypts and authenticates the payload, returning the token payload bytes (for example
   * {@code nonce || ciphertext || tag}). The header, footer and implicit assertion are given as
   * explicit byte slices for the version-specific pre-authentication encoding.
   */
  byte[] encrypt(byte[] payload, byte[] header, byte[] footer, byte[] implicitAssertion);

  /**
   * Verifies the authentication tag and decrypts. Implementations must not return plaintext
   * before authentication has succeeded.
   */
  byte[] decrypt(LocalSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion);
}
