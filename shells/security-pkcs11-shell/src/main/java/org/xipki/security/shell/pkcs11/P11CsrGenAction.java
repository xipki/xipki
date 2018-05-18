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

package org.xipki.security.shell.pkcs11;

import java.security.cert.X509Certificate;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.Hex;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.shell.CsrGenAction;
import org.xipki.security.shell.pkcs11.completer.P11ModuleNameCompleter;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "csr-p11",
    description = "generate CSR request with PKCS#11 device")
@Service
public class P11CsrGenAction extends CsrGenAction {

  @Option(name = "--slot", required = true,
      description = "slot index\n(required)")
  private Integer slotIndex;

  @Option(name = "--id",
      description = "id of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  private String id;

  @Option(name = "--label",
      description = "label of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  private String label;

  @Option(name = "--module",
      description = "name of the PKCS#11 module")
  @Completion(P11ModuleNameCompleter.class)
  private String moduleName = "default";

  @Override
  protected ConcurrentContentSigner getSigner(SignatureAlgoControl signatureAlgoControl)
      throws Exception {
    ParamUtil.requireNonNull("signatureAlgoControl", signatureAlgoControl);

    byte[] idBytes = null;
    if (id != null) {
      idBytes = Hex.decode(id);
    }

    SignerConf conf = getPkcs11SignerConf(moduleName, slotIndex, label,
        idBytes, 1, HashAlgo.getNonNullInstance(hashAlgo), signatureAlgoControl);
    return securityFactory.createSigner("PKCS11", conf, (X509Certificate[]) null);
  }

  public static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Integer slotIndex,
      String keyLabel, byte[] keyId, int parallelism, HashAlgo hashAlgo,
      SignatureAlgoControl signatureAlgoControl) {
    ParamUtil.requireMin("parallelism", parallelism, 1);
    ParamUtil.requireNonNull("hashAlgo", hashAlgo);

    if (slotIndex == null) {
      throw new IllegalArgumentException("slotIndex must not be null");
    }

    if (keyId == null && keyLabel == null) {
      throw new IllegalArgumentException("at least one of keyId and keyLabel must not be null");
    }

    ConfPairs conf = new ConfPairs();
    conf.putPair("parallelism", Integer.toString(parallelism));

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
