/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.client.shell;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.ConfPairs;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.util.Hex;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "cmp-enroll-p11", description = "enroll certificate (PKCS#11 token)")
@Service
public class P11EnrollCertAction extends EnrollCertAction {

  @Option(name = "--slot", required = true, description = "slot index")
  private Integer slotIndex;

  @Option(name = "--key-id",
      description = "id of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  private String keyId;

  @Option(name = "--key-label",
      description = "label of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  private String keyLabel;

  @Option(name = "--module", description = "name of the PKCS#11 module")
  private String moduleName = "default";

  private ConcurrentContentSigner signer;

  @Override
  protected ConcurrentContentSigner getSigner() throws ObjectCreationException {
    if (signer == null) {
      byte[] keyIdBytes = null;
      if (keyId != null) {
        keyIdBytes = Hex.decode(keyId);
      }

      SignerConf signerConf = getPkcs11SignerConf(moduleName, slotIndex, keyLabel,
          keyIdBytes, HashAlgo.getInstance(hashAlgo), getSignatureAlgoControl());
      signer = securityFactory.createSigner("PKCS11", signerConf, (X509Certificate[]) null);
    }
    return signer;
  }

  public static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Integer slotIndex,
      String keyLabel, byte[] keyId, HashAlgo hashAlgo, SignatureAlgoControl signatureAlgoControl) {
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);
    ParamUtil.requireNonNull("slotIndex", slotIndex);

    if (keyId == null && keyLabel == null) {
      throw new IllegalArgumentException("at least one of keyId and keyLabel must not be null");
    }

    ConfPairs conf = new ConfPairs();
    conf.putPair("parallelism", Integer.toString(1));

    if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
      conf.putPair("module", pkcs11ModuleName);
    }

    if (slotIndex != null) {
      conf.putPair("slot", slotIndex.toString());
    }

    if (keyId != null) {
      conf.putPair("key-id", Hex.encode(keyId));
    }

    if (keyLabel != null) {
      conf.putPair("key-label", keyLabel);
    }

    return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
  }

}
