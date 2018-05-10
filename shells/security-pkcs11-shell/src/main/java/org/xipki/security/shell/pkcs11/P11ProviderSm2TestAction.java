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

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.xipki.common.util.StringUtil;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.pkcs11.provider.XiSM2ParameterSpec;

/**
 * TODO.
 * @author Lijun Liao
 * @since 3.0.1
 */

@Command(scope = "xi", name = "p11prov-sm2-test",
    description = "test the SM2 implementation of Xipki PKCS#11 JCA/JCE provider")
@Service
public class P11ProviderSm2TestAction extends P11SecurityAction {

  @Option(name = "--id",
      description = "id of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  protected String id;

  @Option(name = "--label",
      description = "label of the private key in the PKCS#11 device\n"
          + "either keyId or keyLabel must be specified")
  protected String label;

  @Option(name = "--verbose", aliases = "-v",
      description = "show object information verbosely")
  private Boolean verbose = Boolean.FALSE;

  @Option(name = "--ida",
      description = "IDA (ID user A)")
  protected String ida;

  @Override
  protected Object execute0() throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS11", XiSecurityConstants.PROVIDER_NAME_XIPKI);
    ks.load(null, null);
    if (verbose.booleanValue()) {
      println("available aliases:");
      Enumeration<?> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias2 = (String) aliases.nextElement();
        println("    " + alias2);
      }
    }

    String alias = getAlias();
    println("alias: " + alias);
    PrivateKey key = (PrivateKey) ks.getKey(alias, null);
    if (key == null) {
      println("could not find key with alias '" + alias + "'");
      return null;
    }

    Certificate cert = ks.getCertificate(alias);
    if (cert == null) {
      println("could not find certificate to verify signature");
      return null;
    }

    String sigAlgo = "SM3withSM2";
    println("signature algorithm: " + sigAlgo);
    Signature sig = Signature.getInstance(sigAlgo, XiSecurityConstants.PROVIDER_NAME_XIPKI);

    if (StringUtil.isNotBlank(ida)) {
      sig.setParameter(new XiSM2ParameterSpec(ida.getBytes()));
    }

    sig.initSign(key);

    byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    sig.update(data);
    byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
    println("signature created successfully");

    Signature ver = Signature.getInstance(sigAlgo, "BC");
    if (StringUtil.isNotBlank(ida)) {
      ver.setParameter(new SM2ParameterSpec(ida.getBytes()));
    }

    ver.initVerify(cert.getPublicKey());
    ver.update(data);
    boolean valid = ver.verify(signature);
    println("signature valid: " + valid);
    return null;
  }

  private String getAlias() {
    if (label != null) {
      return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
          "#keylabel-", label);
    } else {
      return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
          "#keyid-", id.toLowerCase());
    }
  }

}
