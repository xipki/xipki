// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.jni.NativePKCS11Loader;
import org.xipki.pkcs11.wrapper.jni.PKCS11;
import org.xipki.util.codec.Args;

import java.io.IOException;

/**
 * PKCS#11 module loader.
 *
 * @author Lijun Liao (xipki)
 */

public class PKCS11Loader {

  private static final Logger LOG = LoggerFactory.getLogger(PKCS11Loader.class);

  private final String rawPkcs11ModulePath;

  private final String className;

  private final String pkcs11ModulePath;

  /**
   * @param pkcs11ModulePath
   *        The path of the module; e.g. "/path/to/libhsm.so".
   */
  public PKCS11Loader(String pkcs11ModulePath) {
    this.rawPkcs11ModulePath = Args.notNull(pkcs11ModulePath,
        "pkcs11ModulePath");

    String path;
    if (pkcs11ModulePath.startsWith("java:")
        || pkcs11ModulePath.startsWith("xihsm:")) {
      int pathBeginIndex;
      if (pkcs11ModulePath.startsWith("java:")) {
        final int prefixLen = "java:".length();
        int sepClassEndIndex = pkcs11ModulePath.indexOf(":", prefixLen);
        this.className = pkcs11ModulePath.substring(
            prefixLen, sepClassEndIndex);
        pathBeginIndex = sepClassEndIndex + 1;
      } else {
        this.className = "org.xipki.pkcs11.xihsm.XiPKCS11";
        pathBeginIndex = "xihsm:".length();
      }
      path = pkcs11ModulePath.substring(pathBeginIndex);
    } else {
      this.className = null;
      path = rawPkcs11ModulePath;
    }

    if (path.startsWith("~/")) {
      String userhome = System.getProperty("user.home");
      if (userhome != null) {
        path = userhome + pkcs11ModulePath.substring(1);
      }
    }
    this.pkcs11ModulePath = path;
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module;
   * e.g. "slbck.dll". Tries to load the PKCS#11 wrapper native library from
   * the class path (jar file) or library path.
   *
   * @return An instance of Module that is connected to the given PKCS#11
   *         module.
   * @exception IOException
   *            If connecting to the named module fails.
   *
   */
  public PKCS11 newPKCS11() throws IOException, PKCS11Exception {
    Args.notNull(pkcs11ModulePath, "pkcs11ModulePath");
    PKCS11 pkcs11;
    if (className != null) {
      try {
        pkcs11 = (PKCS11) PKCS11Module.class.getClassLoader()
            .loadClass(className).getConstructor().newInstance();
      } catch (Exception e) {
        String message = "error initializing PKCS#11 module '"
            + rawPkcs11ModulePath  + "'";
        LOG.error(message, e);
        throw new IOException(message + ":" + e.getMessage(), e);
      }
    } else {
      pkcs11 = NativePKCS11Loader.newPKCS11();
    }

    pkcs11.initModule(pkcs11ModulePath);

    try {
      long flags = PKCS11T.CKF_OS_LOCKING_OK;
      LOG.info("C_Initialize: flags=0x{}", Functions.toFullHex(flags));
      pkcs11.C_Initialize(flags);
    } catch (PKCS11Exception e) {
      if (e.errorCode() == PKCS11T.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        LOG.error("pkcs11.C_Initialize with " +
            "CKR_CRYPTOKI_ALREADY_INITIALIZED", e);
      } else {
        try {
          pkcs11.C_Finalize();
        } catch (PKCS11Exception e2) {
        }
        throw e;
      }
    }

    LOG.info("LogPKCS11 initialized PKCS11: pkcs11ModulePath={}",
        pkcs11ModulePath);
    return pkcs11;
  }

}
