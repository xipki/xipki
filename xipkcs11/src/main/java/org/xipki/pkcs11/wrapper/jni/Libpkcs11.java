// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

/**
 * JNI class to communicate with real PKCS#11 device via so/dll library.
 *
 * @author Lijun Liao (xipki)
 */
class Libpkcs11 {

  native static byte getArch();

  native static void initializeLibrary();

  native static void closeLibrary();

  native static long initModule(int moduleId, byte[] modulePath);

  native static long closeModule(int moduleId);

  native static int getVersion(int moduleId);

  native static byte[] query(
      int op, byte[] resp,
      int moduleId,  // module id
      long id,       // slotId, hSession
      long id2,      // object id, userType, flags,
      long id3,      // extra id,
      int size,      // size or count
      byte[] data1, byte[] data2,
      long ckm,     byte[] mechParams,
      byte[] template1, byte[] template2);

}
