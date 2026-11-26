// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author palos
 */
public interface Upload {
  byte[] getBytes() throws IOException;

  long getSize();

  boolean isEmpty();

  String getOriginalFilename();

  String getContentType();

  default InputStream getInputStream() throws IOException {
    return new ByteArrayInputStream(getBytes());
  }
}
