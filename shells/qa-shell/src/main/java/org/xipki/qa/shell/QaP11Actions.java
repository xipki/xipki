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

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.provider.XiPkcs11Provider;
import org.xipki.security.pkcs11.provider.XiSM2ParameterSpec;
import org.xipki.shell.Completers;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;

import java.security.*;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Set;

/**
 * Actions for PKCS#11 security.
 *
 * @author Lijun Liao
 */

public class QaP11Actions {

  @Command(scope = "qa", name = "p11prov-sm2-test",
      description = "test the SM2 implementation of Xipki PKCS#11 JCA/JCE provider")
  @Service
  public static class P11provSm2Test extends P11SecurityAction {

    @Option(name = "--ida", description = "IDA (ID user A)")
    protected String ida;

    @Override
    protected Object execute1(PrivateKey key, Certificate cert)
        throws Exception {
      String signAlgo = "SM3withSM2";
      println("signature algorithm: " + signAlgo);
      Signature sig = Signature.getInstance(signAlgo);

      if (StringUtil.isNotBlank(ida)) {
        sig.setParameter(new XiSM2ParameterSpec(StringUtil.toUtf8Bytes(ida)));
      }

      sig.initSign(key);

      byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      sig.update(data);
      byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
      println("signature created successfully");

      Signature ver = Signature.getInstance(signAlgo, "BC");
      if (StringUtil.isNotBlank(ida)) {
        ver.setParameter(new SM2ParameterSpec(StringUtil.toUtf8Bytes(ida)));
      }

      ver.initVerify(cert.getPublicKey());
      ver.update(data);
      boolean valid = ver.verify(signature);
      println("signature valid: " + valid);
      return null;
    } // method execute0

  } // class P11provSm2Test

  @Command(scope = "qa", name = "p11prov-test",
      description = "test the Xipki PKCS#11 JCA/JCE provider")
  @Service
  public static class P11provTest extends P11SecurityAction {

    @Option(name = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--rsa-pss",
        description = "whether to use the RSAPSS for the POPO computation\n"
            + "(only applied to RSA key)")
    private Boolean rsaPss = Boolean.FALSE;

    @Option(name = "--dsa-plain",
        description = "whether to use the Plain DSA for the POPO computation\n"
            + "(only applied to ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
        description = "whether to use the chinese GM algorithm for the POPO computation\n"
            + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    @Override
    protected Object execute1(PrivateKey key, Certificate cert)
        throws Exception {
      PublicKey pubKey = cert.getPublicKey();

      SignAlgo signAlgo = getSignatureAlgo(pubKey);
      println("signature algorithm: " + signAlgo);
      Signature sig = Signature.getInstance(signAlgo.getJceName());
      sig.initSign(key);

      byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      sig.update(data);
      byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
      println("signature created successfully");

      String provName = "BC";
      Signature ver = Signature.getInstance(signAlgo.getJceName(), provName);
      ver.initVerify(pubKey);
      ver.update(data);
      boolean valid = ver.verify(signature);
      println("signature valid: " + valid);
      return null;
    } // method execute0

    private SignAlgo getSignatureAlgo(PublicKey pubKey)
        throws NoSuchAlgorithmException {
      SignatureAlgoControl algoControl = new SignatureAlgoControl(rsaPss, dsaPlain, gm);
      return SignAlgo.getInstance(pubKey, HashAlgo.getInstance(hashAlgo), algoControl);
    }

  } // class P11provTest

  protected abstract static class P11SecurityAction extends XiAction {

    protected static final String DEFAULT_P11MODULE_NAME =
        P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    @Completion(P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

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
    protected Boolean verbose = Boolean.FALSE;

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    protected abstract Object execute1(PrivateKey key, Certificate cert)
        throws Exception;

    protected String getAlias()
        throws IllegalCmdParamException {
      if (label != null && id == null) {
        return StringUtil.concat(moduleName, "#slotindex-", Integer.toString(slotIndex),
            "#keylabel-", label);
      } else if (label == null && id != null) {
        return StringUtil.concat(moduleName, "#slotindex-", Integer.toString(slotIndex),
            "#keyid-", id.toLowerCase());
      } else {
        throw new IllegalCmdParamException(
            "exactly one of id or label should be specified");
      }
    }

    @Override
    protected Object execute0()
        throws Exception {
      KeyStore ks = KeyStore.getInstance("PKCS11", XiPkcs11Provider.PROVIDER_NAME);
      ks.load(null, null);
      if (verbose) {
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

      return execute1(key, cert);
    }

  } // class P11SecurityAction

  @Service
  public static class P11ModuleNameCompleter extends DynamicEnumCompleter {

    @Reference (optional = true)
    private P11CryptServiceFactory p11CryptServiceFactory;

    @Override
    protected Set<String> getEnums() {
      Set<String> names = p11CryptServiceFactory.getModuleNames();
      if (CollectionUtil.isEmpty(names)) {
        return Collections.emptySet();
      }
      return names;
    }

  } // class P11ModuleNameCompleter
}
