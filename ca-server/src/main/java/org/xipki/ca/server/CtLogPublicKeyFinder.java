/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.server;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.CaServerConf.CtLogConf;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;

/**
 * CtLog public key finder.
 *
 * @author Lijun Liao
 */
public class CtLogPublicKeyFinder {

  private static final Logger LOG = LoggerFactory.getLogger(CtLogPublicKeyFinder.class);

  private final byte[][] logIds;

  private final PublicKey[] publicKeys;

  private final boolean withPublicKeys;

  public CtLogPublicKeyFinder(CtLogConf conf)
      throws IOException {
    String keydirName = conf.getKeydir();
    File[] keyFiles = null;
    if (keydirName != null && !keydirName.isEmpty()) {
      keydirName = IoUtil.expandFilepath(keydirName, true);
      keyFiles = new File(keydirName).listFiles(pathname -> {
        String name = pathname.getName();
        return pathname.isFile()
            && (name.endsWith(".pem") || name.endsWith(".der")
                || name.endsWith(".key") || name.endsWith(".publickey"));
      });
    }

    if (keyFiles == null || keyFiles.length == 0) {
      this.logIds = null;
      this.publicKeys = null;
      this.withPublicKeys = false;
      return;
    }

    final int size = keyFiles.length;
    List<byte[]> logIdList = new ArrayList<>(size);
    List<PublicKey> publicKeyList = new ArrayList<>(size);

    for (File m : keyFiles) {
      byte[] keyBytes = IoUtil.read(m, true);
      keyBytes = X509Util.toDerEncoded(keyBytes);
      try {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyBytes);
        byte[] logId = HashAlgo.SHA256.hash(spki.getEncoded());
        PublicKey key = KeyUtil.generatePublicKey(spki);

        logIdList.add(logId);
        publicKeyList.add(key);
        LOG.info("loaded CtLog public key {}", m.getName());
      } catch (IOException | InvalidKeySpecException ex) {
        LogUtil.error(LOG, ex, "could not load CtLog public key " + m.getName());
      }
    }

    this.logIds = logIdList.toArray(new byte[0][0]);
    this.publicKeys = publicKeyList.toArray(new PublicKey[0]);
    this.withPublicKeys = logIds.length > 0;
  }

  public PublicKey getPublicKey(byte[] logId) {
    if (withPublicKeys) {
      for (int i = 0; i < logIds.length; i++) {
        if (Arrays.equals(logId, logIds[i])) {
          return publicKeys[i];
        }
      }
    }

    return null;
  }

}
