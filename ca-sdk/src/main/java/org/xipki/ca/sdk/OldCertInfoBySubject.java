// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class OldCertInfoBySubject extends OldCertInfo {

  private byte[] subject;

  private byte[] san;

  public byte[] getSubject() {
    return subject;
  }

  public void setSubject(byte[] subject) {
    this.subject = subject;
  }

  public byte[] getSan() {
    return san;
  }

  public void setSan(byte[] san) {
    this.san = san;
  }
}
