// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.xipki.security.EdECConstants;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.Args;
import org.xipki.util.Base64;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * SubjectPublicKeyInfo entry for benchmark enrollment test.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class CaEnrollBenchKeyEntry {

  public static final class RSAKeyEntry extends CaEnrollBenchKeyEntry {

    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65535);

    private static final AlgorithmIdentifier keyAlgId =
        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

    private SubjectPublicKeyInfo spki;

    private KeyPairGenerator keyPairGenerator;

    public RSAKeyEntry(int keysize, boolean reuse) throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalArgumentException("invalid RSA keysize " + keysize);
      }

      if (!reuse) {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        return;
      }

      KeyPairGenerator kp = KeyPairGenerator.getInstance("RSA");
      kp.initialize(keysize);
      RSAPublicKey publicKey = (RSAPublicKey) kp.generateKeyPair().getPublic();
      this.spki = new SubjectPublicKeyInfo(keyAlgId,
          new org.bouncycastle.asn1.pkcs.RSAPublicKey(publicKey.getModulus(), publicKey.getPublicExponent()));
    }

    private static BigInteger base64ToInt(String base64Str) {
      return new BigInteger(1, Base64.decode(base64Str));
    }

    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception {
      if (spki != null) {
        return spki;
      }

      RSAPublicKey publicKey = (RSAPublicKey) keyPairGenerator.generateKeyPair().getPublic();
      return new SubjectPublicKeyInfo(keyAlgId,
          new org.bouncycastle.asn1.pkcs.RSAPublicKey(publicKey.getModulus(), publicKey.getPublicExponent()));
    }

  } // class RSAKeyEntry

  public static final class ECKeyEntry extends CaEnrollBenchKeyEntry {

    private SubjectPublicKeyInfo spki;

    private KeyPairGenerator keyPairGenerator;

    public ECKeyEntry(final ASN1ObjectIdentifier curveOid, boolean reuse) throws Exception {
      if (!reuse) {
        if (!EdECConstants.isEdwardsOrMontgomeryCurve(curveOid)) {
          keyPairGenerator = initKeyPairGenrator(curveOid);
        }
        return;
      }

      this.spki = buildSpki(curveOid);
    }

    private SubjectPublicKeyInfo buildSpki(ASN1ObjectIdentifier curveOid) throws Exception {
      KeyPair keypair;
      if (EdECConstants.isEdwardsOrMontgomeryCurve(Args.notNull(curveOid, "curveOid"))) {
        keypair = KeyUtil.generateEdECKeypair(curveOid, null);
        return KeyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
      } else {
        KeyPairGenerator kpgen = keyPairGenerator != null ? keyPairGenerator : initKeyPairGenrator(curveOid);
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid);
        KeyPair kp = kpgen.generateKeyPair();

        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int fieldBitSize = pub.getParams().getCurve().getField().getFieldSize();
        byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), fieldBitSize);
        return new SubjectPublicKeyInfo(algId, keyData);
      }
    }

    private static KeyPairGenerator initKeyPairGenrator(ASN1ObjectIdentifier curveOid) throws Exception {
      String curveName = AlgorithmUtil.getCurveName(curveOid);
      if (curveName == null) {
        curveName = curveOid.getId();
      }

      KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", "BC");
      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
      kpgen.initialize(spec);
      return kpgen;
    }

    @Override
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
      return spki;
    }

  } // class ECKeyEntry

  public abstract SubjectPublicKeyInfo getSubjectPublicKeyInfo() throws Exception;

}
