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

package org.xipki.ca.api.profile;

import java.math.BigInteger;
import java.security.spec.DSAParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.util.Args;

/**
 * TODO.
 * @author Lijun Liao
 *
 */

public class KeypairGenControl {

  public static class ForbiddenKeypairGenControl extends KeypairGenControl {
    public static final ForbiddenKeypairGenControl INSTANCE = new ForbiddenKeypairGenControl();

    private ForbiddenKeypairGenControl() {
    }
  }

  // CHECKSTYLE:SKIP
  public static class InheritCAKeypairGenControl extends KeypairGenControl {
    public static final InheritCAKeypairGenControl INSTANCE = new InheritCAKeypairGenControl();

    private InheritCAKeypairGenControl() {
    }
  }

  // CHECKSTYLE:SKIP
  public static class RSAKeypairGenControl extends KeypairGenControl {

    private final int keysize;

    private final BigInteger publicExponent;

    private final AlgorithmIdentifier keyAlgorithm;

    public RSAKeypairGenControl(int keysize) {
      this(keysize, null, null);
    }

    public RSAKeypairGenControl(int keysize, BigInteger publicExponent,
        ASN1ObjectIdentifier keyAlgorithmOid) {
      if (keysize < 1024 || keysize % 512 != 0) {
        throw new IllegalArgumentException("invalid keysize " + keysize);
      }

      this.keysize = keysize;
      this.publicExponent = (publicExponent != null) ? publicExponent
          : BigInteger.valueOf(0x10001);
      this.keyAlgorithm = new AlgorithmIdentifier(
          (keyAlgorithmOid != null) ? keyAlgorithmOid : PKCSObjectIdentifiers.rsaEncryption,
          DERNull.INSTANCE);
    }

    public int getKeysize() {
      return keysize;
    }

    public BigInteger getPublicExponent() {
      return publicExponent;
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

  }

  // CHECKSTYLE:SKIP
  public static class ECKeypairGenControl extends KeypairGenControl {

    private final ASN1ObjectIdentifier curveOid;

    private final AlgorithmIdentifier keyAlgorithm;

    public ECKeypairGenControl(ASN1ObjectIdentifier curveOid) {
      this(curveOid, null);
    }

    public ECKeypairGenControl(ASN1ObjectIdentifier curveOid,
        ASN1ObjectIdentifier keyAlgorithmOid) {
      this.curveOid = Args.notNull(curveOid, "curveOid");
      this.keyAlgorithm = new AlgorithmIdentifier(
          (keyAlgorithmOid != null) ? keyAlgorithmOid : X9ObjectIdentifiers.id_ecPublicKey,
           curveOid);
    }

    public ASN1ObjectIdentifier getCurveOid() {
      return curveOid;
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

  }

  // CHECKSTYLE:SKIP
  public static class DSAKeypairGenControl extends KeypairGenControl {

    private final DSAParameterSpec parameterSpec;

    private final AlgorithmIdentifier keyAlgorithm;

    // CHECKSTYLE:SKIP
    public DSAKeypairGenControl(int pLength) {
      this(pLength, 0, null);
    }

    // CHECKSTYLE:SKIP
    public DSAKeypairGenControl(int pLength, int qLength, ASN1ObjectIdentifier keyAlgorithmOid) {
      if (pLength < 1024 | pLength % 1024 != 0) {
        throw new IllegalArgumentException("invalid pLength " + pLength);
      }

      if (qLength == 0) {
        if (pLength < 2048) {
          qLength = 160;
        } else if (pLength < 3072) {
          qLength = 224;
        } else {
          qLength = 256;
        }
      }

      this.parameterSpec = DSAParameterCache.getDSAParameterSpec(pLength, qLength, null);
      this.keyAlgorithm = new AlgorithmIdentifier(
          (keyAlgorithmOid != null) ? keyAlgorithmOid : X9ObjectIdentifiers.id_dsa,
          new DSAParameter(parameterSpec.getP(), parameterSpec.getQ(), parameterSpec.getG()));
    }

    public DSAKeypairGenControl(BigInteger p, BigInteger q, BigInteger g,
        ASN1ObjectIdentifier keyAlgorithmOid) {
      this.parameterSpec = new DSAParameterSpec(p, q, g);

      this.keyAlgorithm = new AlgorithmIdentifier(
          (keyAlgorithmOid != null) ? keyAlgorithmOid : X9ObjectIdentifiers.id_dsa,
          new DSAParameter(p, q, g));
    }

    public DSAParameterSpec getParameterSpec() {
      return parameterSpec;
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

  }

}
