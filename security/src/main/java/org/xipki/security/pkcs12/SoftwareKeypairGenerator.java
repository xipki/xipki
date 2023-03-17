// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.password.PasswordResolver;
import org.xipki.security.EdECConstants;
import org.xipki.security.KeypairGenerator;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.ConfPairs;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.*;
import java.security.spec.DSAParameterSpec;
import java.util.Locale;

/**
 * Software-based keypair generator.
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */
public class SoftwareKeypairGenerator extends KeypairGenerator {

  private final SecureRandom random;

  public SoftwareKeypairGenerator(SecureRandom random) {
    this.random = random == null ? new SecureRandom() : random;
  }

  @Override
  public void initialize0(ConfPairs conf, PasswordResolver passwordResolver) {
  }

  @Override
  public PrivateKeyInfo generateKeypair(String keyspec) throws XiSecurityException {
    if (!supports(keyspec)) {
      throw new XiSecurityException(name + " cannot generate keypair of keyspec " + keyspec);
    }

    try {
      return generateKeypair0(keyspec);
    } catch (XiSecurityException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new XiSecurityException(ex);
    }
  }

  private PrivateKeyInfo generateKeypair0(String keyspec) throws Exception {
    String[] tokens = keyspec.split("/");
    String type = tokens[0].toUpperCase(Locale.ROOT);

    switch (type) {
      case "RSA": {
        int keysize = Integer.parseInt(tokens[1]);
        if (keysize > 4096) {
          throw new XiSecurityException("keysize too large");
        }

        KeyPair kp = KeyUtil.generateRSAKeypair(keysize, rsaE, random);
        return KeyUtil.toPrivateKeyInfo((RSAPrivateCrtKey) kp.getPrivate());
      }
      case "EC": {
        ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(tokens[1]);

        KeyPair kp = KeyUtil.generateECKeypair(curveOid, random);
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int fieldBitLength = pub.getParams().getCurve().getField().getFieldSize();

        byte[] publicKey = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), fieldBitLength);

        /*
         * ECPrivateKey ::= SEQUENCE {
         *   Version INTEGER { ecPrivkeyVer1(1) }
         *                   (ecPrivkeyVer1),
         *   privateKey      OCTET STRING,
         *   parameters [0]  Parameters OPTIONAL,
         *   publicKey  [1]  BIT STRING OPTIONAL
         * }
         *
         * Since the EC domain parameters are placed in the PKCS#8’s privateKeyAlgorithm field,
         * the optional parameters field in an ECPrivateKey must be omitted. A Cryptoki
         * application must be able to unwrap an ECPrivateKey that contains the optional publicKey
         * field; however, what is done with this publicKey field is outside the scope of
         * Cryptoki.
         */
        int orderBitLength = pub.getParams().getOrder().bitLength();
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        return new PrivateKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid),
            new org.bouncycastle.asn1.sec.ECPrivateKey(
                orderBitLength, priv.getS(), new DERBitString(publicKey), null));
      }
      case "DSA": {
        int pLength = Integer.parseInt(tokens[1]);
        int qLength = Integer.parseInt(tokens[2]);
        DSAParameterSpec spec = DSAParameterCache.getDSAParameterSpec(pLength, qLength, null);
        KeyPair kp = KeyUtil.generateDSAKeypair(spec, random);
        DSAParameter parameter = new DSAParameter(spec.getP(), spec.getQ(), spec.getG());
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);

        byte[] publicKey = new ASN1Integer(((DSAPublicKey) kp.getPublic()).getY()).getEncoded();

        // DSA private keys are represented as BER-encoded ASN.1 type INTEGER.
        DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();
        return new PrivateKeyInfo(algId, new ASN1Integer(priv.getX()), null, publicKey);
      }
      case "ED25519":
      case "ED448":
      case "X25519":
      case "X448": {
        ASN1ObjectIdentifier curveId = EdECConstants.getCurveOid(keyspec);
        KeyPair kp = KeyUtil.generateEdECKeypair(curveId, random);
        return PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
      }
      default: {
        throw new IllegalArgumentException("unknown keyspec " + keyspec);
      }
    }
  }

  @Override
  public boolean isHealthy() {
    return true;
  }

  @Override
  public void close() throws IOException {
  }

}
