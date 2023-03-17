// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.Args;

import java.security.cert.CRLReason;
import java.util.*;

/**
 * The CRLReason enumeration specifies the reason that a certificate
 * is revoked, as defined in <a href="http://www.ietf.org/rfc/rfc3280.txt">
 * RFC 3280: Internet X.509 Public Key Infrastructure Certificate and CRL
 * Profile</a>.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public enum CrlReason {

  /**
   * This reason indicates that it is unspecified as to why the
   * certificate has been revoked.
   */
  UNSPECIFIED(0, "unspecified"),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to end-entity certificates only.
   */
  KEY_COMPROMISE(1, "keyCompromise"),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to certificate authority (CA) certificates only.
   */
  CA_COMPROMISE(2, "cACompromise"),

  /**
   * This reason indicates that the subject's name or other information
   * has changed.
   */
  AFFILIATION_CHANGED(3, "affiliationChanged"),

  /**
   * This reason indicates that the certificate has been superseded.
   */
  SUPERSEDED(4, "superseded"),

  /**
   * This reason indicates that the certificate is no longer needed.
   */
  CESSATION_OF_OPERATION(5, "cessationOfOperation"),

  /**
   * This reason indicates that the certificate has been put on hold.
   */
  CERTIFICATE_HOLD(6, "certificateHold"),

  /**
   * This reason indicates that the certificate was previously on hold
   * and should be removed from the CRL. It is for use with delta CRLs.
   */
  REMOVE_FROM_CRL(8, "removeFromCRL"),

  /**
   * This reason indicates that the privileges granted to the subject of
   * the certificate have been withdrawn.
   */
  PRIVILEGE_WITHDRAWN(9, "privilegeWithdrawn"),

  /**
   * This reason indicates that it is known or suspected that the
   * certificate subject's private key has been compromised. It applies
   * to authority attribute (AA) certificates only.
   */
  AA_COMPROMISE(10, "aACompromise");

  public static final List<CrlReason> PERMITTED_CLIENT_CRLREASONS = Collections.unmodifiableList(
      Arrays.asList(CrlReason.UNSPECIFIED, CrlReason.KEY_COMPROMISE,
          CrlReason.AFFILIATION_CHANGED, CrlReason.SUPERSEDED, CrlReason.CESSATION_OF_OPERATION,
          CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN));

  private static final Map<Integer, CrlReason> REASONS = new HashMap<>();

  private final int code;
  private final String desription;

  CrlReason(int code, String description) {
    this.code = code;
    this.desription = description;
  }

  public int getCode() {
    return code;
  }

  public String getDescription() {
    return desription;
  }

  static {
    for (CrlReason value : CrlReason.values()) {
      REASONS.put(value.code, value);
    }
  }

  public static CrlReason forReasonCode(int reasonCode) {
    CrlReason ret = REASONS.get(reasonCode);
    if (ret != null) {
      return ret;
    }

    throw new IllegalArgumentException("invalid CrlReason code " + reasonCode);
  }

  public static CrlReason fromReason(CRLReason reason) {
    if (reason == CRLReason.AA_COMPROMISE) {
      return AA_COMPROMISE;
    } else if (reason == CRLReason.AFFILIATION_CHANGED) {
      return AFFILIATION_CHANGED;
    } else if (reason == CRLReason.CA_COMPROMISE) {
      return CA_COMPROMISE;
    } else if (reason == CRLReason.CERTIFICATE_HOLD) {
      return CERTIFICATE_HOLD;
    } else if (reason == CRLReason.CESSATION_OF_OPERATION) {
      return CESSATION_OF_OPERATION;
    } else if (reason == CRLReason.KEY_COMPROMISE) {
      return KEY_COMPROMISE;
    } else if (reason == CRLReason.PRIVILEGE_WITHDRAWN) {
      return PRIVILEGE_WITHDRAWN;
    } else if (reason == CRLReason.REMOVE_FROM_CRL) {
      return REMOVE_FROM_CRL;
    } else if (reason == CRLReason.SUPERSEDED) {
      return SUPERSEDED;
    } else if (reason == CRLReason.UNSPECIFIED) {
      return UNSPECIFIED;
    } else {
      throw new IllegalArgumentException("invald CRLReason " + reason);
    }
  }

  public static CrlReason forNameOrText(String text) {
    Args.notNull(text, "text");
    for (CrlReason value : values()) {
      if (value.desription.equalsIgnoreCase(text)
          || value.name().equalsIgnoreCase(text)
          || Integer.toString(value.code).equals(text)) {
        return value;
      }
    }

    throw new IllegalArgumentException("invalid CrlReason " + text);
  }

}
