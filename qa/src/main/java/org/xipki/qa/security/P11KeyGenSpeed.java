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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.util.BenchmarkExecutor;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.util.Args.notNull;

/**
 * Speed test of PKCS#11 keypair generation.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class P11KeyGenSpeed extends BenchmarkExecutor {

  public static class DSA extends P11KeyGenSpeed {

    private final int plength;

    private final int qlength;

    public DSA(P11Slot slot, byte[] id, int plength, int qlength)
        throws Exception {
      super(slot, id, "PKCS#11 DSA key generation\nplength: " + plength + "\nqlength: " + qlength);
      this.plength = plength;
      this.qlength = qlength;
    }

    @Override
    protected void genKeypair()
        throws Exception {
      P11IdentityId objId = slot.generateDSAKeypair(plength, qlength, getControl());
      slot.removeIdentity(objId);
    }

  } // class DSA

  public static class EC extends P11KeyGenSpeed {

    private final ASN1ObjectIdentifier curveOid;

    public EC(P11Slot slot, byte[] id, ASN1ObjectIdentifier curveOid)
        throws Exception {
      super(slot, id, "PKCS#11 EC key generation\ncurve: " + curveOid.getId());
      this.curveOid = notNull(curveOid, "curveOid");
    }

    @Override
    protected void genKeypair()
        throws Exception {
      P11IdentityId objId = slot.generateECKeypair(curveOid, getControl());
      slot.removeIdentity(objId);
    }

  } // class EC

  public static class RSA extends P11KeyGenSpeed {

    private final int keysize;

    private final BigInteger publicExponent;

    public RSA(P11Slot slot, byte[] id, int keysize, BigInteger publicExponent)
        throws Exception {
      super(slot, id, "PKCS#11 RSA key generation\nkeysize: " + keysize
          + "\npublic exponent: " + publicExponent);
      this.keysize = keysize;
      this.publicExponent = publicExponent;
    }

    @Override
    protected void genKeypair()
        throws Exception {
      P11IdentityId objId = slot.generateRSAKeypair(keysize, publicExponent, getControl());
      slot.removeIdentity(objId);
    }

  } // class RSA

  public static class SM2 extends P11KeyGenSpeed {
    public SM2(P11Slot slot, byte[] id)
        throws Exception {
      super(slot, id, "PKCS#11 SM2 key generation");
    }

    @Override
    protected void genKeypair()
        throws Exception {
      P11IdentityId objId = slot.generateSM2Keypair(getControl());
      slot.removeIdentity(objId);
    }

  } // class SM2

  class Testor implements Runnable {

    @Override
    public void run() {
      while (!stop() && getErrorAccout() < 1) {
        try {
          genKeypair();
          account(1, 0);
        } catch (Exception ex) {
          LOG.error("P11KeyGenSpeed.Testor.run()", ex);
          account(1, 1);
        }
      }
    }

  } // class Testor

  protected final P11Slot slot;

  private static final Logger LOG = LoggerFactory.getLogger(P11KeyGenSpeed.class);

  private byte[] id;

  private AtomicLong idx = new AtomicLong(System.currentTimeMillis());

  public P11KeyGenSpeed(P11Slot slot, byte[] id, String description) {
    super(description);
    this.slot = notNull(slot, "slot");
    this.id = id;
  }

  protected abstract void genKeypair()
      throws Exception;

  protected P11NewKeyControl getControl() {
    return new P11NewKeyControl(id, "speed-" + idx.getAndIncrement());
  }

  @Override
  protected Runnable getTestor()
      throws Exception {
    return new Testor();
  }

}
