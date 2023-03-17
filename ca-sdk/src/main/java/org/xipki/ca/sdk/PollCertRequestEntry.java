// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class PollCertRequestEntry {

  /*
   * In SCEP: this field is null.
   */
  private BigInteger id;

  private X500NameType subject;

  public BigInteger getId() {
    return id;
  }

  public void setId(BigInteger id) {
    this.id = id;
  }

  public X500NameType getSubject() {
    return subject;
  }

  public void setSubject(X500NameType subject) {
    this.subject = subject;
  }

}
