// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.cmp.client;

import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.ConcurrentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.util.codec.Args;

import java.security.SecureRandom;

/**
 * CMP requestor.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class Requestor {

  private static final X500Name NULL_GENERALNAME = new X500Name(new RDN[0]);

  private final GeneralName name;

  private Requestor(X500Name name) {
    this.name = new GeneralName(Args.notNull(name, "name"));
  }

  public GeneralName name() {
    return name;
  }

  public static class PbmMacCmpRequestor extends Requestor {

    private final SecureRandom random = new SecureRandom();

    private final char[] password;

    private final byte[] senderKID;

    private final HashAlgo owf;

    private final int iterationCount;

    private final SignAlgo mac;

    public PbmMacCmpRequestor(char[] password, byte[] senderKID,
                              HashAlgo owf, int iterationCount, SignAlgo mac) {
      super(NULL_GENERALNAME);
      this.password = password;
      this.senderKID = senderKID;
      this.owf = owf;
      this.iterationCount = iterationCount;
      this.mac = mac;
    }

    public char[] password() {
      return password;
    }

    public byte[] senderKID() {
      return senderKID;
    }

    public PBMParameter parameter() {
      return new PBMParameter(randomSalt(), owf.algorithmIdentifier(),
          iterationCount, mac.algorithmIdentifier());
    }

    private byte[] randomSalt() {
      byte[] bytes = new byte[64];
      random.nextBytes(bytes);
      return bytes;
    }
  } // class PbmMacCmpRequestor

  public static class SignatureCmpRequestor extends Requestor {

    private final ConcurrentSigner signer;

    public SignatureCmpRequestor(ConcurrentSigner signer) {
      super(getSignerSubject(signer));
      this.signer = signer;
    }

    public ConcurrentSigner signer() {
      return signer;
    }

    private static X500Name getSignerSubject(ConcurrentSigner signer) {
      if (Args.notNull(signer, "signer").getX509Cert() == null) {
        throw new IllegalArgumentException(
            "requestor without certificate is not allowed");
      }

      return signer.getX509Cert().subject();
    }

  } // class SignatureCmpRequestor

}
