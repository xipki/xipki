// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.jni.JniResp;
import org.xipki.pkcs11.wrapper.jni.PKCS11;
import org.xipki.pkcs11.wrapper.type.CkVersion;

/**
 * PKCS#11 implementation which communicates with XiHSM.
 *
 * @author Lijun Liao (xipki)
 */
public class XiPKCS11 extends PKCS11 {

  @Override
  protected Arch arch() {
    return XiLibpkcs11.arch();
  }

  @Override
  protected void initModule(int moduleId, String modulePath)
      throws PKCS11Exception {
    XiLibpkcs11.initModule(moduleId, modulePath);
  }

  @Override
  protected void closeModule(int moduleId) throws PKCS11Exception {
    XiLibpkcs11.closeModule(moduleId);
  }

  public CkVersion getVersion(int moduleId) throws PKCS11Exception {
    int version = XiLibpkcs11.getVersion(moduleId);
    if (version == 0) {
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }
    return new CkVersion((byte) (version >> 8), (byte) version) ;
  }

  @Override
  protected byte[] doQuery(
      int moduleId, int opCode, byte[] resp, long id,
      long id2, long id3, int size, byte[] data, byte[] data2,
      long ckm, byte[] mechParams, byte[] template, byte[] template2) {
    try {
      byte[] payload = XiLibpkcs11.doQuery(opCode, resp, moduleId, id,
          id2, id3, size, data, data2, ckm, mechParams, template, template2);
      boolean allZeros = true;
      for (byte b : resp) {
        if (b != 0) {
          allZeros = false;
          break;
        }
      }

      if (allZeros) {
        JniResp.JniSimpleResp.INSTANCE.writeTo(resp);
      }
      return payload;
    } catch (PKCS11Exception e) {
      new JniResp.JniErrResp(e.getErrorCode()).writeTo(arch(), resp);
      return null;
    }
  }

}
