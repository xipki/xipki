// License Apache License 2.0

package org.xipki.mgmt.web.dto;

/** User-confirmed identity inputs for the deployment-wide Quick Start workflow. */
public class QuickStartRequest extends StrictRequest {
  public String caName;
  public String organization;
  public String country;
  public Boolean confirmed;
}
