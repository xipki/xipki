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

package org.xipki.security.speed.pkcs12;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.common.LoadExecutor;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.util.AlgorithmUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12SignSpeed extends LoadExecutor {

  class Testor implements Runnable {

    private final byte[] data = new byte[1024];

    public Testor() {
      new SecureRandom().nextBytes(data);
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          signer.sign(data);
          account(1, 0);
        } catch (Exception ex) {
          account(1, 1);
        }
      }
    }

  } // class Testor

  protected static final String PASSWORD = "1234";

  private final ConcurrentContentSigner signer;

  public P12SignSpeed(SecurityFactory securityFactory, String signatureAlgorithm,
      byte[] keystore, String description) throws Exception {
    this("PKCS12", securityFactory, signatureAlgorithm, keystore, description);
  }

  public P12SignSpeed(String tokenType, SecurityFactory securityFactory,
      String signatureAlgorithm, byte[] keystore, String description) throws Exception {
    super(description);

    ParamUtil.requireNonNull("securityFactory", securityFactory);
    ParamUtil.requireNonBlank("signatureAlgorithm", signatureAlgorithm);
    ParamUtil.requireNonNull("keystore", keystore);

    SignerConf signerConf = SignerConf.getKeystoreSignerConf(
        new ByteArrayInputStream(keystore), PASSWORD, signatureAlgorithm, 20);
    this.signer = securityFactory.createSigner(tokenType, signerConf, (X509Certificate) null);
  }

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

  // CHECKSTYLE:SKIP
  protected static byte[] getPrecomputedRSAKeystore(int keysize, BigInteger publicExponent)
      throws IOException {
    return getPrecomputedKeystore("rsa-" + keysize + "-0x" + publicExponent.toString(16)
      + ".p12");
  }

  // CHECKSTYLE:SKIP
  protected static byte[] getPrecomputedDSAKeystore(int plength, int qlength) throws IOException {
    return getPrecomputedKeystore("dsa-" + plength + "-" + qlength + ".p12");
  }

  // CHECKSTYLE:SKIP
  protected static byte[] getPrecomputedECKeystore(String curveNamOrOid) throws IOException {
    ASN1ObjectIdentifier oid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNamOrOid);
    if (oid == null) {
      return null;
    }

    return getPrecomputedKeystore("ec-" + oid.getId() + ".p12");
  }

  private static byte[] getPrecomputedKeystore(String filename) throws IOException {
    InputStream in = P12ECSignSpeed.class.getResourceAsStream("/testkeys/" + filename);
    return (in == null) ? null : IoUtil.read(in);
  }

}
