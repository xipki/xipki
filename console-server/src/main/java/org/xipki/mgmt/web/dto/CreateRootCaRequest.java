// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class CreateRootCaRequest extends StrictRequest {
  public String name;
  public String subject;
  public String profile;
  public String serialNumber;
  public String notBefore;
  public String notAfter;
  public Long nextCrlNo;
  public CaConfigurationRequest config;
  public CaKeyRequest key;
}
