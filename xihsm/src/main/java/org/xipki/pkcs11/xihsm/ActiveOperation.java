// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.crypt.MultiPartOperation;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.OperationType;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author Lijun Liao (xipki)
 */
public class ActiveOperation {

  private final AtomicBoolean simpleActiveOp = new AtomicBoolean(false);

  private MultiPartOperation multiActiveOp;

  public OperationType getOperationType() {
    return multiActiveOp != null ? multiActiveOp.getType() : null;
  }

  public void enterSimpleOp() throws HsmException {
    assertNotActive();
    simpleActiveOp.set(true);
  }

  public synchronized void enterMultiOp(MultiPartOperation op)
      throws HsmException {
    assertNotActive();
    this.multiActiveOp = op;
  }

  public synchronized void clearActiveOp() {
    simpleActiveOp.set(false);
    multiActiveOp = null;
  }

  synchronized void clearActiveOp(OperationType op) {
    if (multiActiveOp != null && multiActiveOp.getType() == op) {
      multiActiveOp = null;
    }
  }

  public synchronized void assertNotActive() throws HsmException {
    if (simpleActiveOp.get() || multiActiveOp != null) {
      throw new HsmException(PKCS11T.CKR_OPERATION_ACTIVE,
          "The session is still active for other operation");
    }
  }

  public synchronized MultiPartOperation assertMultiOpInitialized(
      OperationType type) throws HsmException {
    if (multiActiveOp == null || multiActiveOp.getType() != type) {
      throw new HsmException(PKCS11T.CKR_OPERATION_NOT_INITIALIZED,
          "The session has not been initialized for " + type);
    }

    return multiActiveOp;
  }

}
