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

package org.xipki.qa.security;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.*;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.util.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.xipki.util.Args.notBlank;
import static org.xipki.util.Args.notNull;

/**
 * Speed test of PKCS#11 signature creation.
 *
 * @author Lijun Liao
 */

public class JceSignSpeed extends BenchmarkExecutor {

  class Testor implements Runnable {

    private static final int batch = 10;

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
          LOG.error("P11SignSpeed.Testor.run()", ex);
          account(batch, batch);
        }
      }
    }

  } // class Testor

  private static final Logger LOG = LoggerFactory.getLogger(JceSignSpeed.class);

  private final ConcurrentContentSigner signer;

  public JceSignSpeed(SecurityFactory securityFactory, String type, String alias,
                      String signatureAlgorithm, String description, int threads)
          throws ObjectCreationException {
    super(description + "\nsignature algorithm: " + signatureAlgorithm);

    notBlank(signatureAlgorithm, "signatureAlgorithm");

    try {
      SignerConf signerConf = getJceSignerConf(alias, threads,
              SignAlgo.getInstance(signatureAlgorithm));
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
  public final void close() {
  }

  @Override
  protected Runnable getTestor()
      throws Exception {
    return new Testor();
  }

  private static SignerConf getJceSignerConf(String alias, int parallelism, SignAlgo signAlgo) {
    ConfPairs conf = new ConfPairs();
    conf.putPair("parallelism", Integer.toString(parallelism));
    conf.putPair("alias", alias);
    conf.putPair("algo", signAlgo.getJceName());
    return new SignerConf(conf.getEncoded());
  } // method getJceSignerConf

}
