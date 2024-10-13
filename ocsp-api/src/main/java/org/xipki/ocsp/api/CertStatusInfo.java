// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

import org.xipki.security.CertRevocationInfo;
import org.xipki.util.Args;

import java.time.Instant;

/**
 * CertStatus information.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class CertStatusInfo {

  public enum CertStatus {
    GOOD,
    REVOKED,
    UNKNOWN,
    IGNORE,
    ISSUER_UNKNOWN,
    CRL_EXPIRED
  } // class CertStatus

  public enum UnknownCertBehaviour {
    unknown,
    good,
    malformedRequest,
    internalError,
    tryLater
  } // class UnknownCertBehaviour

  public enum UnknownIssuerBehaviour {
    unknown,
    malformedRequest,
    internalError,
    unauthorized,
    tryLater
  } // class UnknownIssuerBehaviour

  private CertStatus certStatus;

  private CertRevocationInfo revocationInfo;

  private Instant thisUpdate;

  private Instant nextUpdate;

  private String certprofile;

  private CertStatusInfo(CertStatus certStatus, Instant thisUpdate, Instant nextUpdate, String certprofile) {
    this.certStatus = Args.notNull(certStatus, "certStatus");
    this.thisUpdate = Args.notNull(thisUpdate, "thisUpdate");
    this.nextUpdate = nextUpdate;
    this.certprofile = certprofile;
  }

  public Instant getThisUpdate() {
    return thisUpdate;
  }

  public void setThisUpdate(Instant thisUpdate) {
    this.thisUpdate = thisUpdate;
  }

  public Instant getNextUpdate() {
    return nextUpdate;
  }

  public void setNextUpdate(Instant nextUpdate) {
    this.nextUpdate = nextUpdate;
  }

  public CertStatus getCertStatus() {
    return certStatus;
  }

  public void setCertStatus(CertStatus certStatus) {
    this.certStatus = Args.notNull(certStatus, "certStatus");
  }

  public CertRevocationInfo getRevocationInfo() {
    return revocationInfo;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public static CertStatusInfo getCrlExpiredStatusInfo() {
    return new CertStatusInfo(CertStatus.CRL_EXPIRED, Instant.now(), null, null);
  }

  public static CertStatusInfo getUnknownCertStatusInfo(Instant thisUpdate, Instant nextUpdate) {
    return new CertStatusInfo(CertStatus.UNKNOWN, thisUpdate, nextUpdate, null);
  }

  public static CertStatusInfo getIgnoreCertStatusInfo(Instant thisUpdate, Instant nextUpdate) {
    return new CertStatusInfo(CertStatus.IGNORE, thisUpdate, nextUpdate, null);
  }

  public static CertStatusInfo getIssuerUnknownCertStatusInfo(Instant thisUpdate, Instant nextUpdate) {
    return new CertStatusInfo(CertStatus.ISSUER_UNKNOWN, thisUpdate, nextUpdate, null);
  }

  public static CertStatusInfo getGoodCertStatusInfo(
      Instant thisUpdate, Instant nextUpdate, String certprofile) {
    return new CertStatusInfo(CertStatus.GOOD, thisUpdate, nextUpdate, certprofile);
  } // method getGoodCertStatusInfo

  public static CertStatusInfo getGoodCertStatusInfo(Instant thisUpdate, Instant nextUpdate) {
    return new CertStatusInfo(CertStatus.GOOD, thisUpdate, nextUpdate, null);
  }

  public static CertStatusInfo getRevokedCertStatusInfo(
      CertRevocationInfo revocationInfo, Instant thisUpdate, Instant nextUpdate, String certprofile) {
    Args.notNull(revocationInfo, "revocationInfo");
    CertStatusInfo ret = new CertStatusInfo(CertStatus.REVOKED, thisUpdate, nextUpdate, certprofile);
    ret.revocationInfo = revocationInfo;
    return ret;
  } // method getRevokedCertStatusInfo

  public static CertStatusInfo getRevokedCertStatusInfo(
      CertRevocationInfo revocationInfo, Instant thisUpdate, Instant nextUpdate) {
    Args.notNull(revocationInfo, "revocationInfo");
    CertStatusInfo ret = new CertStatusInfo(CertStatus.REVOKED, thisUpdate, nextUpdate, null);
    ret.revocationInfo = revocationInfo;
    return ret;
  } // method getRevokedCertStatusInfo

}
