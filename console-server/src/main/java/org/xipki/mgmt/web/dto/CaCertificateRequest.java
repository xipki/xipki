// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class CaCertificateRequest extends StrictRequest {
  public String certificate;
  public List<String> certificateChain;
}
