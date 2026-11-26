// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * Typed management requests reject misspelled or unsupported fields.
 *
 * @author palos
 */
public abstract class StrictRequest {
  public void unknown(String name, Object value) {
    throw new IllegalArgumentException("Unsupported request field");
  }
}
