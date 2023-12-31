// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Set;

/**
 * Extension AuthorityInfoAccess.
 *
 * @author Lijun Liao (xipki)
 */

public class AuthorityInfoAccess extends ValidableConf {

  private boolean includeCaIssuers;

  private boolean includeOcsp;

  private Set<String> ocspProtocols;

  private Set<String> caIssuersProtocols;

  public boolean isIncludeCaIssuers() {
    return includeCaIssuers;
  }

  public void setIncludeCaIssuers(boolean includeCaIssuers) {
    this.includeCaIssuers = includeCaIssuers;
  }

  public boolean isIncludeOcsp() {
    return includeOcsp;
  }

  public void setIncludeOcsp(boolean includeOcsp) {
    this.includeOcsp = includeOcsp;
  }

  public Set<String> getOcspProtocols() {
    return ocspProtocols;
  }

  public void setOcspProtocols(Set<String> ocspProtocols) {
    this.ocspProtocols = ocspProtocols;
  }

  public Set<String> getCaIssuersProtocols() {
    return caIssuersProtocols;
  }

  public void setCaIssuersProtocols(Set<String> caIssuersProtocols) {
    this.caIssuersProtocols = caIssuersProtocols;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class AuthorityInfoAccess
