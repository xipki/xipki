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

package org.xipki.cmpclient.internal;

import static org.xipki.util.Args.notNull;

import java.security.SecureRandom;

import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.X509Cert;

/**
 * CMP requestor.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

abstract class Requestor {

  private final GeneralName name;

  private final boolean signRequest;

  protected Requestor(boolean signRequest, GeneralName name) {
    this.signRequest = signRequest;
    this.name = notNull(name, "name");
  }

  protected Requestor(boolean signRequest, X500Name name) {
    this.signRequest = signRequest;
    this.name = new GeneralName(notNull(name, "name"));
  }

  public boolean signRequest() {
    return signRequest;
  }

  public GeneralName getName() {
    return name;
  }

  static class PbmMacCmpRequestor extends Requestor {

    private final SecureRandom random = new SecureRandom();

    private final char[] password;

    // CHECKSTYLE:SKIP
    private final byte[] senderKID;

    private final HashAlgo owf;

    private final int iterationCount;

    private final SignAlgo mac;

    PbmMacCmpRequestor(boolean signRequest, X500Name x500name, char[] password,
        // CHECKSTYLE:SKIP
        byte[] senderKID, HashAlgo owf, int iterationCount, SignAlgo mac) {
      super(signRequest, x500name);
      this.password = password;
      this.senderKID = senderKID;
      this.owf = owf;
      this.iterationCount = iterationCount;
      this.mac = mac;
    }

    public char[] getPassword() {
      return password;
    }

    // CHECKSTYLE:SKIP
    public byte[] getSenderKID() {
      return senderKID;
    }

    public PBMParameter getParameter() {
      return new PBMParameter(randomSalt(), owf.getAlgorithmIdentifier(),
          iterationCount, mac.getAlgorithmIdentifier());
    }

    public HashAlgo getOwf() {
      return owf;
    }

    public int getIterationCount() {
      return iterationCount;
    }

    public SignAlgo getMac() {
      return mac;
    }

    private byte[] randomSalt() {
      byte[] bytes = new byte[64];
      random.nextBytes(bytes);
      return bytes;
    }
  } // class PbmMacCmpRequestor

  static class SignatureCmpRequestor extends Requestor {

    private final ConcurrentContentSigner signer;

    SignatureCmpRequestor(X509Cert cert) {
      super(false, notNull(cert, "cert").getSubject());
      this.signer = null;
    }

    public SignatureCmpRequestor(boolean signRequest, ConcurrentContentSigner signer,
        SecurityFactory securityFactory) {
      super(signRequest, getSignerSubject(signer));
      this.signer = signer;
    }

    public ConcurrentContentSigner getSigner() {
      return signer;
    }

    private static X500Name getSignerSubject(ConcurrentContentSigner signer) {
      notNull(signer, "signer");
      if (signer.getCertificate() == null) {
        throw new IllegalArgumentException("requestor without certificate is not allowed");
      }

      return signer.getCertificate().getSubject();
    }

  } // class SignatureCmpRequestor

}
