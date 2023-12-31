// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Extension SubjectKeyIdentifierControl.
 *
 * @author Lijun Liao (xipki)
 */

public class SubjectKeyIdentifierControl extends ValidableConf {

  public enum SubjectKeyIdentifierMethod {
    // RFC5280, 4.2.1.2 Method 1: 160 bit SHA1
    METHOD_1,
    // RFC5280, 4.2.1.2 Method 1: 0100_2 || 60 bit LSB of SHA1
    METHOD_2
  }

  private SubjectKeyIdentifierMethod method;

  private String hashAlgo;

  /**
   * Format
   *   - 'L':'&lt;size&gt: Use the left most size bytes.
   *   - 'R':'&lt;size&gt: Use the right most size bytes.
   * <p/>
   * Method to truncate the output of {{@link #getMethod()}} is longer than the expected size,
   */
  private String truncateMethod;

  public SubjectKeyIdentifierMethod getMethod() {
    return method;
  }

  public void setMethod(SubjectKeyIdentifierMethod method) {
    this.method = method;
  }

  public String getHashAlgo() {
    return hashAlgo;
  }

  public void setHashAlgo(String hashAlgo) {
    this.hashAlgo = hashAlgo;
  }

  public String getTruncateMethod() {
    return truncateMethod;
  }

  public void setTruncateMethod(String truncateMethod) {
    this.truncateMethod = truncateMethod;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

} // class AuthorityKeyIdentifier
