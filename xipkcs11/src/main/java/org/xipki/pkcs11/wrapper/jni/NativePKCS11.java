// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkVersion;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * PKCS#11 implementation which communicates with real PKCS#11 device.
 *
 * @author Lijun Liao (xipki)
 */
public class NativePKCS11 extends PKCS11 {

  private static final Logger log =
      LoggerFactory.getLogger(NativePKCS11.class);

  private static Arch arch;

  static boolean initializeLibrary() {
    try {
      Libpkcs11.initializeLibrary();
      log.info("initialized library");
      return true;
    } catch (Throwable t) {
      log.error("initializing library failed", t);
      return false;
    }
  }

  static void closeLibrary() {
    try {
      Libpkcs11.closeLibrary();
    } catch (Throwable t) {
      log.error("closing library failed", t);
    }
  }

  @Override
  protected Arch arch() {
    if (arch == null) {
      byte res = Libpkcs11.getArch();
      boolean littleEndian = (res & 0x80) != 0;
      int longSize = 0x7F & res;
      arch = new Arch(littleEndian, longSize);
    }
    return arch;
  }

  @Override
  protected void initModule(int moduleId, String modulePath)
      throws PKCS11Exception {
    byte[] pathBytes = modulePath.getBytes(StandardCharsets.UTF_8);
    // append \0 at the end
    pathBytes = Arrays.copyOf(pathBytes, pathBytes.length + 1);
    long ckr = Libpkcs11.initModule(moduleId, pathBytes);
    if (ckr != PKCS11T.CKR_OK) {
      throw new PKCS11Exception(ckr);
    }
  }

  @Override
  protected void closeModule(int moduleId)
      throws PKCS11Exception {
    long ckr = Libpkcs11.closeModule(moduleId);
    if (ckr != PKCS11T.CKR_OK) {
      throw new PKCS11Exception(ckr);
    }
  }

  @Override
  protected byte[] doQuery(
      int moduleId, int op,   byte[] resp,
      long id,      long id2, long id3, int size,
      byte[] data,  byte[] data2,
      long ckm,     byte[] mechParams,
      byte[] template, byte[] template2) {
    return Libpkcs11.query(op, resp, moduleId, id, id2, id3, size,
        data, data2, ckm, mechParams, template, template2);
  }

  public CkVersion getVersion(int moduleId) throws PKCS11Exception {
    int version = Libpkcs11.getVersion(moduleId);
    if (version == 0) {
      throw new PKCS11Exception(JniResp.CKR_JNI_NO_MODULE);
    }
    return new CkVersion((byte) (version >> 8), (byte) version) ;
  }

}
