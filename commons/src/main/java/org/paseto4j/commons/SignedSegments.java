/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Validated slices of a public-purpose token payload: message and signature. All arrays are
 * defensively copied.
 */
public record SignedSegments(byte[] message, byte[] signature) {

  public SignedSegments {
    message = message.clone();
    signature = signature.clone();
  }

  @Override
  public byte[] message() {
    return message.clone();
  }

  @Override
  public byte[] signature() {
    return signature.clone();
  }
}
