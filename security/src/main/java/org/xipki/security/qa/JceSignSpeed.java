// Copyright (c) 2013-2024 xipki. All rights reserved.
//
// License Apache License 2.0

package org.xipki.security.qa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.SignerConf;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.ConfPairs;
import org.xipki.util.RandomUtil;
import org.xipki.util.exception.ObjectCreationException;

import java.security.NoSuchAlgorithmException;

/**
 * Speed test of signature creation for JCE based Token.
 *
 * @author Lijun Liao (xipki)
 */

public class JceSignSpeed extends BenchmarkExecutor {

  private class Tester implements Runnable {

    private static final int batch = 10;

    private final byte[][] data = new byte[batch][16];

    public Tester() {
      for (int i = 0; i < data.length; i++) {
        data[i] = RandomUtil.nextBytes(data[i].length);
      }
    }

    @Override
    public void run() {
      while (!stop() && getErrorAccount() < 1) {
        try {
          signer.sign(data);
          account(batch, 0);
        } catch (Exception ex) {
          LOG.error("P11SignSpeed.Tester.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Tester

  private static final Logger LOG = LoggerFactory.getLogger(JceSignSpeed.class);

  private final ConcurrentContentSigner signer;

  public JceSignSpeed(SecurityFactory securityFactory, String type, String alias,
                      String signatureAlgorithm, String description, int threads)
          throws ObjectCreationException {
    super(description + "\nsignature algorithm: " + signatureAlgorithm);

    Args.notBlank(signatureAlgorithm, "signatureAlgorithm");

    try {
      SignerConf signerConf = getJceSignerConf(alias, threads, SignAlgo.getInstance(signatureAlgorithm));
      this.signer = securityFactory.createSigner(type, signerConf, (X509Cert) null);
    } catch (ObjectCreationException ex) {
      close();
      throw ex;
    } catch (NoSuchAlgorithmException ex) {
      close();
      throw new ObjectCreationException(ex.getMessage());
    }
  } // constructor

  @Override
  protected Runnable getTester() throws Exception {
    return new Tester();
  }

  private static SignerConf getJceSignerConf(String alias, int parallelism, SignAlgo signAlgo) {
    ConfPairs conf = new ConfPairs()
        .putPair("parallelism", Integer.toString(parallelism))
        .putPair("alias", alias)
        .putPair("algo", signAlgo.getJceName());
    return new SignerConf(conf);
  } // method getJceSignerConf

}
