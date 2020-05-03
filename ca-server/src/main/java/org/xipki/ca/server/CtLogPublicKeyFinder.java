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

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.CaServerConf.CtLog;
import org.xipki.ca.server.CaServerConf.CtLogServer;
import org.xipki.security.HashAlgo;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.CollectionUtil;
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

  public CtLogPublicKeyFinder(CtLog conf) throws IOException {
    if (conf == null || CollectionUtil.isEmpty(conf.getServers())) {
      this.logIds = null;
      this.publicKeys = null;
    } else {
      final int size = conf.getServers().size();
      List<byte[]> logIdList = new ArrayList<>(size);
      List<PublicKey> publicKeyList = new ArrayList<>(size);

      for (CtLogServer m : conf.getServers()) {
        byte[] keyBytes = m.getPublicKey().readContent();
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
    }

    withPublicKeys = logIds != null && logIds.length > 0;

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
