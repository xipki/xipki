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

package org.xipki.security.custom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.*;
import org.xipki.security.jce.JceSignerBuilder;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.XipkiBaseDir;

import java.io.File;
import java.lang.reflect.Constructor;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The Signer Factory uses SANSEC HSM via the vendor's java SDK.
 * This is an example to show how to create signature using vendors's JCE provider.
 *
 * <p>
 * The configuration files must be put in the folder
 * <code>$XIPKI_BASEDIR/security/sansec-jce</code>.
 * Each HSM has one configuration file, which is either <code>swsds.ini</code> or
 * <code>swsds-&lt;name&gt;.ini</code>.
 * Signer for HSM with configuration file <code>swsds.ini</code> or
 * <code>swsds-&lt;name&gt;.ini</code>
 * has the signer-type <code>sansec</code> or <code>sansec-&lt;name&gt;</code> respectively.
 *
 * <p>
 * The keys in HSM should be created using other tools, e.g. the tools provided by the vendor.
 *
 * <p>
 * To use this class in CA server and OCSP server, you have to configure the <code>ca.json</code>
 * and <code>ocsp.json</code> respectively as follows:
 * <pre>
 *      "signerFactories": [
 *          "org.xipki.security.custom.SansecSignerFactory"
 *      ]
 * </pre>
 *
 * Additionally, you need to copy the vendor's jar files to: 1) the tomcat's <code>lib</code> folder
 * for the OCSP and CA, 2) <code>xipki-cli-&lt;version&gt;/lib/ext</code> of CLI.
 *
 * <p>
 * You may use the command xi:csr-jce in the CLI to generate the CSR.
 *
 * @author Lijun Liao
 */
public class SansecSignerFactory implements SignerFactory {

  private static final class InitStatus {
    // 0: un-initialized, 1: initialized successfully, 2: initialization failed
    private final AtomicInteger status = new AtomicInteger();
    private String details = "";
  }

  private static final Logger LOG;

  private static final Set<String> types;

  private static final Map<String, Provider> providerMap = new HashMap<>();

  private static final Map<String, InitStatus> initStatusMap = new HashMap<>();

  private static final Map<String, String> confFileMap = new HashMap<>();

  static {
    LOG = LoggerFactory.getLogger(SansecSignerFactory.class);
    XipkiBaseDir.init();
    try {
      File sansecDir = IoUtil.expandFilepath(new File("security/sansec-jce"), true);
      if (!sansecDir.exists()) {
        LOG.info("found no SANSEC configuration directory " + sansecDir);
      } else {
        File[] files = sansecDir.listFiles((dir, name) -> name.equals("swsds.ini")
            || (name.startsWith("swsds-") && name.endsWith(".ini")));
        if (files == null) {
          LOG.info("found no SANSEC configuration file");
        } else {
          for (File file : files) {
            String fn = file.getName();
            String type;
            if ("swsds.ini".equals(fn)) {
              type = "sansec";
          } else {
            type = "sansec-" + fn.substring("swsds-".length(),
                fn.length() - ".ini".length()).toLowerCase(Locale.ROOT);
          }
            String path = file.getCanonicalPath();
            confFileMap.put(type, path);
            initStatusMap.put(type, new InitStatus());
            LOG.info("assign SANSEC signer type {} to the configuration file {}", type, path);
          }
        }
      }
    } catch (Exception e) {
      LogUtil.error(LOG, e, "error while initializing " + SansecSignerFactory.class.getName());
    }

    types = Collections.unmodifiableSet(confFileMap.keySet());
  }

  private InitStatus init(String type) {
    InitStatus initStatus = initStatusMap.get(type);
    synchronized (initStatusMap) {
      if (initStatus.status.get() != 0) {
        return initStatus;
      }

      String confFile = confFileMap.get(type);

      try {
        Constructor<?> constructor = Class.forName("com.sansec.jce.provider.SwxaProvider")
            .getConstructor(String.class, // deviceFactoryName
                String.class); // userConfigFile
        Provider provider = (Provider) constructor.newInstance(null, confFile);

        // Use random to test whether it works. You may use other method.
        SecureRandom secureRandom = SecureRandom.getInstance("RND", provider);
        secureRandom.nextInt();

        initStatus.status.set(1);
        providerMap.put(type, provider);
      } catch (Throwable t) {
        initStatus.status.set(2);
        Throwable cause = t.getCause();

        String msg = "cannot initialize SANSEC SwxaProvider " + type;
        if (cause != null) {
          // exception message: SWR_CARD_OPERATION_DENY:1021002
          if (t.getCause().getMessage().contains("1021002")) {
            msg += ", details: no permission to access to SANSEC HSM, " +
                "please login, and restart this system.";
          }
        }
        initStatus.details = msg;
        LogUtil.error(LOG, cause == null ? t : cause, msg);
      }
    }

    return initStatus;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return types;
  }

  @Override
  public boolean canCreateSigner(String type) {
    return types.contains(type.toLowerCase(Locale.ROOT));
  }

  /**
   * The configuration is name-value pairs as follows:
   * <ul>
   *   <li>parallelism: specify how many parallel signing processes are allowed.</li>
   *   <li>alias: key alias. For SANSEC it is the keyId in decimal</li>
   *   <li>algo: signature algorithm</li>
   * </ul>
   */
  @Override
  public ConcurrentContentSigner newSigner(
      String type, SignerConf conf, X509Cert[] certificateChain)
      throws ObjectCreationException {
    type = type.toLowerCase(Locale.ROOT);
    if (!types.contains(type)) {
      throw new ObjectCreationException("unknown signer type " + type);
  }

    String str = conf.getConfValue("parallelism");
    int parallelism = 20;
    if (str != null) {
      try {
        parallelism = Integer.parseInt(str);
      } catch (NumberFormatException ex) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }

      if (parallelism < 1) {
        throw new ObjectCreationException("invalid parallelism " + str);
      }
    }

    str = conf.getConfValue("alias");
    if (str == null) {
      throw new ObjectCreationException("alias is not specified");
    }
    int keyId = Integer.parseInt(str);

    String algoName = conf.getConfValue("algo");
    if (algoName == null) {
      throw new ObjectCreationException("algo is not specified");
    }

    try {
      InitStatus initStatus = init(type);
      if (initStatus.status.get() != 1) {
        throw new ObjectCreationException(initStatus.details);
      }

      SignAlgo algo = SignAlgo.getInstance(algoName);
      String keyAlgoName;
      String bcKeyAlgoName;
      if (algo.isSM2SigAlgo()) {
        keyAlgoName = "SM2";
        bcKeyAlgoName = "EC";
      } else if (algo.isRSAPkcs1SigAlgo() || algo.isRSAPSSSigAlgo()) {
        keyAlgoName = "RSA";
        bcKeyAlgoName = "RSA";
      } else if (algo.isECDSASigAlgo() || algo.isPlainECDSASigAlgo()) {
        keyAlgoName = "EC";
        bcKeyAlgoName = "EC";
      } else {
        throw new ObjectCreationException("unsupported algo " + algoName);
      }

      Provider provider = providerMap.get(type);

      // Method to read create PrivateKey and PublicKey object.
      // SANSEC use KeyPairGenerator.generateKeyPair to read the keypair-
      // No new keypair will be generated here.
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance(keyAlgoName, provider);
      kpGen.initialize(keyId << 16);
      KeyPair kp = kpGen.generateKeyPair();

      PublicKey publicKey = KeyFactory.getInstance(bcKeyAlgoName, "BC")
              .generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

      return new JceSignerBuilder(kp.getPrivate(), publicKey, certificateChain, provider)
          .createSigner(algo, parallelism);
    } catch (GeneralSecurityException | XiSecurityException ex) {
      throw new ObjectCreationException(ex.getMessage(), ex);
    }
  }

  @Override
  public void refreshToken(String type) throws XiSecurityException {
  }
}
