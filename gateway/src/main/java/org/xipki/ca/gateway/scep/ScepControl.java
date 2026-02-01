// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 * SCEP control.
 *
 * @author Lijun Liao (xipki)
 */

public class ScepControl {

  private static final long DFLT_MAX_SIGNINGTIME_BIAS = 5L * 60; // 5 minutes

  private boolean includeCaCert = true;

  private boolean includeCertChain = false;

  private boolean includeSignerCert = true;

  private boolean supportGetCrl = false;

  private long maxSigningTimeBias = DFLT_MAX_SIGNINGTIME_BIAS;

  public boolean isIncludeCaCert() {
    return includeCaCert;
  }

  public void setIncludeCaCert(boolean includeCaCert) {
    this.includeCaCert = includeCaCert;
  }

  public boolean isIncludeCertChain() {
    return includeCertChain;
  }

  public void setIncludeCertChain(boolean includeCertChain) {
    this.includeCertChain = includeCertChain;
  }

  public boolean isIncludeSignerCert() {
    return includeSignerCert;
  }

  public void setIncludeSignerCert(boolean includeSignerCert) {
    this.includeSignerCert = includeSignerCert;
  }

  public boolean isSupportGetCrl() {
    return supportGetCrl;
  }

  public void setSupportGetCrl(boolean supportGetCrl) {
    this.supportGetCrl = supportGetCrl;
  }

  public long maxSigningTimeBias() {
    return maxSigningTimeBias;
  }

  public void setMaxSigningTimeBias(long maxSigningTimeBias) {
    this.maxSigningTimeBias = maxSigningTimeBias;
  }

  public static ScepControl parse(JsonMap json) throws CodecException {
    ScepControl scep = new ScepControl();

    Boolean b = json.getBool("includeCaCert");
    if (b != null) {
      scep.setIncludeCaCert(b);
    }

    b = json.getBool("includeCertChain");
    if (b != null) {
      scep.setIncludeCertChain(b);
    }

    b = json.getBool("includeSignerCert");
    if (b != null) {
      scep.setIncludeSignerCert(b);
    }

    b = json.getBool("supportGetCrl");
    if (b != null) {
      scep.setSupportGetCrl(b);
    }

    Long l = json.getLong("maxSigningTimeBias");
    if (l != null) {
      scep.setMaxSigningTimeBias(l);
    }

    return scep;
  }

}
