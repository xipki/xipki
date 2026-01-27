// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.xipki.pkcs11.xihsm.StoreSlotInfo;

/**
 * @author Lijun Liao (xipki)
 */
public interface PersistStore extends Store {

  StoreSlotInfo[] getSlotInfos();

  long[] getSlotIds();

}
