// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class XiP11Object {

  protected final long handle;

  protected final long objectClass;

  public XiP11Object(long handle, long objectClass) {
    this.handle = handle;
    this.objectClass = objectClass;
  }

}
