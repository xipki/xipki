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

package org.xipki.qa.security.benchmark.pkcs12;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P12SignSpeed extends BenchmarkExecutor {

  class Testor implements Runnable {

    private static final int batch = 16;

    private final byte[][] data = new byte[batch][16];

    public Testor() {
      for (int i = 0; i < data.length; i++) {
        new SecureRandom().nextBytes(data[i]);
      }
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          signer.sign(data);
          account(batch, 0);
        } catch (Exception ex) {
          LOG.error("P12SignSpeed.Testor.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Testor

  protected static final String PASSWORD = "1234";

  private static Logger LOG = LoggerFactory.getLogger(P12SignSpeed.class);

  private final ConcurrentContentSigner signer;

  public P12SignSpeed(SecurityFactory securityFactory, String signatureAlgorithm,
      byte[] keystore, String description, int threads) throws Exception {
    this("PKCS12", securityFactory, signatureAlgorithm, keystore, description, threads);
  }

  public P12SignSpeed(String tokenType, SecurityFactory securityFactory,
      String signatureAlgorithm, byte[] keystore, String description, int threads)
          throws Exception {
    super(description);

    Args.notNull(securityFactory, "securityFactory");
    Args.notBlank(signatureAlgorithm, "signatureAlgorithm");
    Args.notNull(keystore, "keystore");

    SignerConf signerConf = getKeystoreSignerConf(new ByteArrayInputStream(keystore), PASSWORD,
        signatureAlgorithm, threads + Math.max(2, threads * 5 / 4));
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

  private static SignerConf getKeystoreSignerConf(InputStream keystoreStream,
      String password, String signatureAlgorithm, int parallelism) throws IOException {
    ConfPairs conf = new ConfPairs("password", password);
    conf.putPair("algo", signatureAlgorithm);
    conf.putPair("parallelism", Integer.toString(parallelism));
    conf.putPair("keystore", "base64:" + Base64.encodeToString(IoUtil.read(keystoreStream)));
    return new SignerConf(conf.getEncoded());
  }
}
