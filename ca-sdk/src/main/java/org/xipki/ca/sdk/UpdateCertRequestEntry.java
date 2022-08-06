package org.xipki.ca.sdk;

import java.math.BigInteger;
import java.util.List;

public class UpdateCertRequestEntry extends EnrollCertRequestEntry {

  private OldCertInfo oldCert;

  public OldCertInfo getOldCert() {
    return oldCert;
  }

  public void setOldCert(OldCertInfo oldCert) {
    this.oldCert = oldCert;
  }

}
