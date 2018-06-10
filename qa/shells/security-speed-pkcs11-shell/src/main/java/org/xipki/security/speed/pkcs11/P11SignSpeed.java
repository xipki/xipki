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

package org.xipki.security.speed.pkcs11;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.qa.BenchmarkExecutor;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.pkcs11.P11NewKeyControl;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.util.ConfPairs;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.ObjectCreationException;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11SignSpeed extends BenchmarkExecutor {

  class Testor implements Runnable {

    final byte[] data = new byte[1024];

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

  private static final Logger LOG = LoggerFactory.getLogger(P11SignSpeed.class);

  private final P11Slot slot;

  private final ConcurrentContentSigner signer;

  private final P11ObjectIdentifier objectId;

  public P11SignSpeed(SecurityFactory securityFactory, P11Slot slot, String signatureAlgorithm,
      P11ObjectIdentifier objectId, String description) throws ObjectCreationException {
    super(description + "\nsignature algorithm: " + signatureAlgorithm);

    ParamUtil.requireNonNull("securityFactory", securityFactory);
    ParamUtil.requireNonNull("slot", slot);
    ParamUtil.requireNonBlank("signatureAlgorithm", signatureAlgorithm);
    ParamUtil.requireNonNull("objectId", objectId);

    this.slot = slot;
    this.objectId = objectId;

    P11SlotIdentifier slotId = slot.getSlotId();
    SignerConf signerConf = getPkcs11SignerConf(slot.getModuleName(),
        slotId.getId(), objectId.getId(), signatureAlgorithm, 20);
    try {
      this.signer = securityFactory.createSigner("PKCS11", signerConf, (X509Certificate) null);
    } catch (ObjectCreationException ex) {
      shutdown();
      throw ex;
    }
  }

  @Override
  protected void shutdown() {
    try {
      slot.removeIdentity(objectId);
    } catch (Exception ex) {
      LogUtil.error(LOG, ex, "could not delete PKCS#11 key " + objectId);
    }
  }

  protected static P11NewKeyControl getNewKeyControl() {
    P11NewKeyControl control = new P11NewKeyControl();
    control.setExtractable(true);
    return control;
  }

  @Override
  protected Runnable getTestor() throws Exception {
    return new Testor();
  }

  private static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Long slotId, byte[] keyId,
      String signatureAlgorithm, int parallelism) {
    ConfPairs conf = new ConfPairs("algo", signatureAlgorithm);
    conf.putPair("parallelism", Integer.toString(parallelism));

    if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
      conf.putPair("module", pkcs11ModuleName);
    }

    if (slotId != null) {
      conf.putPair("slot-id", slotId.toString());
    }

    if (keyId != null) {
      conf.putPair("key-id", Hex.encode(keyId));
    }

    return new SignerConf(conf.getEncoded());
  }

}
