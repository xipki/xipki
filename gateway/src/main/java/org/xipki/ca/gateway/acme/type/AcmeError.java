// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme.type;

/**
 * ACME Error.
 *
 * @author Lijun Liao (xipki)
 */
public enum AcmeError {

  /**
   * The request specified an account that does not exist.
   */
  accountDoesNotExist,

  /**
   * The request specified a certificate to be revoked that has already been
   * revoked.
   */
  alreadyRevoked,

  /**
   * The CSR is unacceptable (e.g., due to a short key).
   */
  badCSR,

  /**
   * The client sent an unacceptable anti-replay nonce.
   */
  badNonce,

  /**
   * The JWS was signed by a public key the server does not support.
   */
  badPublicKey,

  /**
   * The revocation reason provided is not allowed by the server.
   */
  badRevocationReason,

  /**
   * The JWS was signed with an algorithm the server does not support.
   */
  badSignatureAlgorithm,

  /**
   * Certification Authority Authorization (CAA) records forbid the CA from
   * issuing a certificate.
   */
  caa,

  /**
   * Specific error conditions are indicated in the "subproblems" array.
   */
  compound,

  /**
   * The server could not connect to validation target.
   */
  connection,

  /**
   * There was a problem with a DNS query during identifier validation.
   */
  dns,

  /**
   * The request must include a value for the "externalAccountBinding" field.
   */
  externalAccountRequired,

  /**
   * Response received didn't match the challenge's requirements.
   */
  incorrectResponse,

  /**
   * A contact URL for an account was invalid.
   */
  invalidContact,

  /**
   * The request message was malformed.
   */
  malformed,

  /**
   * The request attempted to finalize an order that is not ready to be
   * finalized.
   */
  orderNotReady,

  /**
   * The request exceeds a rate limit.
   */
  rateLimited,

  /**
   * The server will not issue certificates for the identifier.
   */
  rejectedIdentifier,

  /**
   * The server experienced an internal error.
   */
  serverInternal,

  /**
   * The server received a TLS error during validation.
   */
  tls,

  /**
   * The client lacks sufficient authorization.
   */
  unauthorized,

  /**
   * A contact URL for an account used an unsupported protocol scheme.
   */
  unsupportedContact,

  /**
   * An identifier is of an unsupported type.
   */
  unsupportedIdentifier,

  /**
   * Visit the "instance" URL and take actions specified there.
   */
  userActionRequired;

  private final String qualifiedCode;

  AcmeError() {
    qualifiedCode = "urn:ietf:params:acme:error:" + name();
  }

  public String qualifiedCode() {
    return qualifiedCode;
  }

}
