// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.io.IOException;

/**
 * DNS error: malformed message, failed query, or failed DNSSEC validation. The latter
 * has a {@link Reason}.
 *
 * @author Lijun Liao (xipki)
 */
public class DnsException extends IOException {

  /**
   * Reason of a DNSSEC validation failure.
   */
  public enum Reason {
    MALFORMED,
    MISSING_RRSIG,
    /** RRSIG covers another type, or the class is not IN. */
    RRSIG_MISMATCH,
    /** The RRset was expanded from a wildcard: not supported. */
    WILDCARD,
    INVALID_LABELS,
    /** The signer is not the owner or an ancestor of it, as required for the type. */
    INVALID_SIGNER,
    SIGNATURE_EXPIRED,
    SIGNATURE_NOT_YET_VALID,
    UNSUPPORTED_ALGORITHM,
    NO_MATCHING_KEY,
    /** The matching DNSKEY is not a zone key, has protocol != 3 or is revoked. */
    DNSKEY_INVALID,
    INVALID_SIGNATURE,
    NO_DS,
    NO_DNSKEY,
    /** No DNSKEY matches the DS records or the trust anchors. */
    DS_MISMATCH,
    NO_TRUST_ANCHOR,
    DNAME,
    LIMIT_EXCEEDED,
    QUERY_FAILED
  }

  private final Reason reason;

  public DnsException(String message) {
    super(message);
    this.reason = null;
  }

  public DnsException(String message, Throwable cause) {
    super(message, cause);
    this.reason = null;
  }

  /**
   * Creates a DNSSEC validation failure.
   */
  public DnsException(Reason reason, String message) {
    super("DNSSEC " + reason + ": " + message);
    this.reason = reason;
  }

  /**
   * Returns the reason of a DNSSEC validation failure, or {@code null} for other errors.
   */
  public Reason reason() {
    return reason;
  }

}
