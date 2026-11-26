// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.util.List;
import org.xipki.mgmt.web.core.*;

/**
 * @author palos
 */
public class RepublishRequest extends StrictRequest {
  public String caName;
  public List<String> publisherNames;
  public Integer numThreads = 5;

  public String getCaName() {
    return caName;
  }

  public void setCaName(String value) {
    caName = value;
  }

  public List<String> getPublisherNames() {
    return publisherNames;
  }

  public void setPublisherNames(List<String> value) {
    publisherNames = value;
  }

  public Integer getNumThreads() {
    return numThreads;
  }

  public void setNumThreads(Object value) {
    if (!(value instanceof Integer)) {
      throw new IllegalArgumentException("Thread count must be an integer");
    }
    numThreads = (Integer) value;
  }
}
