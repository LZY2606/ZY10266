/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.security.SignatureException;

/**
 * Version-specific cryptographic operations for public (asymmetric) tokens. Implementations live
 * in the version modules and declare their signature layout; the shared staging is handled by
 * {@link PublicTokenPipeline}.
 */
public interface PublicScheme {

  TokenAlgorithm algorithm();

  /** The signature layout of the decoded token payload. */
  PayloadLayout layout();

  /**
   * Signs the payload and returns the signature. The header, footer and implicit assertion are
   * given as explicit byte slices for the version-specific pre-authentication encoding.
   */
  byte[] sign(byte[] payload, byte[] header, byte[] footer, byte[] implicitAssertion);

  /** Verifies the signature over the message, throwing {@link SignatureException} on failure. */
  void verify(SignedSegments segments, byte[] header, byte[] footer, byte[] implicitAssertion)
      throws SignatureException;
}
