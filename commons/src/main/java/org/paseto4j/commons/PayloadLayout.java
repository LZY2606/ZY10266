/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Conditions.verify;

import java.util.Arrays;
import java.util.Locale;

/**
 * Declares the byte layout of a decoded token payload (nonce/tag for local tokens, signature for
 * public tokens). Splitting only happens after the payload length has been validated, so callers
 * never see {@link IndexOutOfBoundsException} for malformed input.
 */
public final class PayloadLayout {

  private final int nonceLength;
  private final int tagLength;
  private final int signatureLength;

  private PayloadLayout(int nonceLength, int tagLength, int signatureLength) {
    this.nonceLength = nonceLength;
    this.tagLength = tagLength;
    this.signatureLength = signatureLength;
  }

  /** Layout for local tokens: {@code nonce || ciphertext || tag}. */
  public static PayloadLayout local(int nonceLength, int tagLength) {
    return new PayloadLayout(nonceLength, tagLength, -1);
  }

  /** Layout for public tokens: {@code message || signature}. */
  public static PayloadLayout signed(int signatureLength) {
    return new PayloadLayout(-1, -1, signatureLength);
  }

  public LocalSegments splitLocal(byte[] payload) {
    requireNonNull(payload, "payload");
    verify(
        payload.length >= nonceLength + tagLength,
        format(
            Locale.ROOT,
            "Token payload is too short: expected at least %d bytes but got %d",
            nonceLength + tagLength,
            payload.length));
    byte[] nonce = Arrays.copyOfRange(payload, 0, nonceLength);
    byte[] tag = Arrays.copyOfRange(payload, payload.length - tagLength, payload.length);
    byte[] cipherText = Arrays.copyOfRange(payload, nonceLength, payload.length - tagLength);
    return new LocalSegments(nonce, cipherText, tag);
  }

  public SignedSegments splitSigned(byte[] payload) {
    requireNonNull(payload, "payload");
    verify(
        payload.length >= signatureLength,
        format(
            Locale.ROOT,
            "Token payload is too short: expected at least %d bytes but got %d",
            signatureLength,
            payload.length));
    byte[] signature =
        Arrays.copyOfRange(payload, payload.length - signatureLength, payload.length);
    byte[] message = Arrays.copyOfRange(payload, 0, payload.length - signatureLength);
    return new SignedSegments(message, signature);
  }
}
