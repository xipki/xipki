package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class UpdateCertRequestEntry extends EnrollCertRequestEntry {

  private OldCertInfo oldCert;

  public OldCertInfo getOldCert() {
    return oldCert;
  }

  public void setOldCert(OldCertInfo oldCert) {
    this.oldCert = oldCert;
  }

}
