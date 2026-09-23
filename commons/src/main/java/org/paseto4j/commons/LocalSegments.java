/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Validated slices of a local-purpose token payload: nonce, ciphertext and authentication tag.
 * All arrays are defensively copied.
 */
public record LocalSegments(byte[] nonce, byte[] cipherText, byte[] tag) {

  public LocalSegments {
    nonce = nonce.clone();
    cipherText = cipherText.clone();
    tag = tag.clone();
  }

  @Override
  public byte[] nonce() {
    return nonce.clone();
  }

  @Override
  public byte[] cipherText() {
    return cipherText.clone();
  }

  @Override
  public byte[] tag() {
    return tag.clone();
  }
}
