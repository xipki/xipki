package org.xipki.ca.gateway.acme.type;

/**
 * ACME Error.
 */
public class AcmeError {

  private AcmeError() {
  }

  public static final String ACME_PREFIX = "urn:ietf:params:acme:error:";

  /**
   * The request specified an account that does not exist.
   */
  public static final String accountDoesNotExist = ACME_PREFIX + "accountDoesNotExist";

  /**
   * The request specified a certificate to be revoked that has already been revoked.
   */
  public static final String alreadyRevoked = ACME_PREFIX + "alreadyRevoked";

  /**
   * The CSR is unacceptable (e.g., due to a short key).
   */
  public static final String badCSR = ACME_PREFIX + "badCSR";

  /**
   * The client sent an unacceptable anti-replay nonce.
   */
  public static final String badNonce = ACME_PREFIX + "badNonce";

  /**
   * The JWS was signed by a public key the server does not support.
   */
  public static final String badPublicKey = ACME_PREFIX + "badPublicKey";

  /**
   * The revocation reason provided is not allowed by the server.
   */
  public static final String badRevocationReason = ACME_PREFIX + "badRevocationReason";

  /**
   * The JWS was signed with an algorithm the server does not support.
   */
  public static final String badSignatureAlgorithm = ACME_PREFIX + "v";

  /**
   * Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate.
   */
  public static final String caa = ACME_PREFIX + "caa";

  /**
   * Specific error conditions are indicated in the "subproblems" array.
   */
  public static final String compound = ACME_PREFIX + "compound";

  /**
   * The server could not connect to validation target.
   */
  public static final String connection = ACME_PREFIX + "connection";

  /**
   * There was a problem with a DNS query during identifier validation.
   */
  public static final String dns = ACME_PREFIX + "dns";

  /**
   * The request must include a value for the "externalAccountBinding" field.
   */
  public static final String externalAccountRequired = ACME_PREFIX + "externalAccountRequired";

  /**
   * Response received didn't match the challenge's requirements.
   */
  public static final String incorrectResponse = ACME_PREFIX + "incorrectResponse";

  /**
   * A contact URL for an account was invalid.
   */
  public static final String invalidContact = ACME_PREFIX + "invalidContact";

  /**
   * The request message was malformed.
   */
  public static final String malformed = ACME_PREFIX + "malformed";

  /**
   * The request attempted to finalize an order that is not ready to be finalized.
   */
  public static final String orderNotReady = ACME_PREFIX + "orderNotReady";

  /**
   * The request exceeds a rate limit.
   */
  public static final String rateLimited = ACME_PREFIX + "rateLimited";

  /**
   * The server will not issue certificates for the identifier.
   */
  public static final String rejectedIdentifier = ACME_PREFIX + "rejectedIdentifier";

  /**
   * The server experienced an internal error.
   */
  public static final String serverInternal = ACME_PREFIX + "serverInternal";

  /**
   * The server received a TLS error during validation.
   */
  public static final String tls = ACME_PREFIX + "tls";

  /**
   * The client lacks sufficient authorization.
   */
  public static final String unauthorized = ACME_PREFIX + "unauthorized";

  /**
   * A contact URL for an account used an unsupported protocol scheme.
   */
  public static final String unsupportedContact = ACME_PREFIX + "unsupportedContact";

  /**
   * An identifier is of an unsupported type.
   */
  public static final String unsupportedIdentifier = ACME_PREFIX + "unsupportedIdentifier";

  /**
   * Visit the "instance" URL and take actions specified there.
   */
  public static final String userActionRequired = ACME_PREFIX + "userActionRequired";

}
