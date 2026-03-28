// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.bridge;

import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;

import java.security.GeneralSecurityException;

/**
 * CMP Callback interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface CmpCallback {

  byte[] decrypt(EncryptedKey encryptedKey) throws GeneralSecurityException;

  byte[] decrypt(EncryptedValue encryptedValue) throws GeneralSecurityException;

}
