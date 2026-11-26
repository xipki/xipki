// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class ImportCaRequest extends StrictRequest {
  public String name;
  public String certificate;
  public List<String> certificateChain;
  public Long nextCrlNo;
  public CaConfigurationRequest config;
  public CaKeyRequest key;
  public Boolean acceptUnknownRevocation;
}
