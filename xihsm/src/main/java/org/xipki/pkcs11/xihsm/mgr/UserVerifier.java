// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.xihsm.util.HsmException;

/**
 * @author Lijun Liao (xipki)
 */
public interface UserVerifier {

  void verify(long userType, byte[] pin) throws HsmException;

}
