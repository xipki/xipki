package org.xipki.security.pkcs12;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.password.PasswordResolver;
import org.xipki.security.KeypairGenerator;
import org.xipki.security.EdECConstants;
import org.xipki.security.KeypairGenResult;
import org.xipki.security.XiSecurityException;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.KeyUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.DSAParameterSpec;
import java.util.Locale;

/**
 * Software-based keypair generator.
 * @author Lijun Liao
 * @since 5.4.0
 */
public class SoftwareKeypairGenerator implements KeypairGenerator {

  private static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

  private final SecureRandom random;

  private String name;

  public SoftwareKeypairGenerator(SecureRandom random) {
    this.random = random == null ? new SecureRandom() : random;
  }

  @Override
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public void initialize(String conf, PasswordResolver passwordResolver)
      throws XiSecurityException {
  }

  @Override
  public boolean supports(String keyspec) {
    String[] tokens = keyspec.toUpperCase(Locale.ROOT).split("/");
    if (tokens.length == 0) {
      return false;
    }
    switch (tokens[0]) {
      case "RSA":
      case "DSA":
      case "EC":
      case "ED25519":
      case "ED448":
      case "X25519":
      case "X448":
        return true;
    }

    return false;
  }

  @Override
  public KeypairGenResult generateKeypair(String keyspec)
      throws XiSecurityException {
    try {
      return generateKeypair0(keyspec);
    } catch (XiSecurityException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new XiSecurityException(ex);
    }
  }

  private KeypairGenResult generateKeypair0(String keyspec) throws Exception {
    String[] tokens = keyspec.toUpperCase(Locale.ROOT).split("/");

    PrivateKeyInfo privateKey;
    SubjectPublicKeyInfo publicKeyInfo;

    switch (tokens[0]) {
      case "RSA": {
        int keysize = Integer.parseInt(tokens[1]);
        if (keysize > 4096) {
          throw new XiSecurityException("keysize too large");
        }

        BigInteger publicExponent = null;
        if (tokens.length > 2) {
          publicExponent = new BigInteger(tokens[2].substring("0x".length()), 16);
        }

        KeyPair kp = KeyUtil.generateRSAKeypair(keysize, publicExponent, random);
        java.security.interfaces.RSAPublicKey rsaPubKey =
            (java.security.interfaces.RSAPublicKey) kp.getPublic();

        publicKeyInfo = new SubjectPublicKeyInfo(ALGID_RSA,
            new RSAPublicKey(rsaPubKey.getModulus(), rsaPubKey.getPublicExponent()));

        /*
         * RSA private keys are BER-encoded according to PKCS #1’s RSAPrivateKey ASN.1 type.
         *
         * RSAPrivateKey ::= SEQUENCE {
         *   version           Version,
         *   modulus           INTEGER,  -- n
         *   publicExponent    INTEGER,  -- e
         *   privateExponent   INTEGER,  -- d
         *   prime1            INTEGER,  -- p
         *   prime2            INTEGER,  -- q
         *   exponent1         INTEGER,  -- d mod (p-1)
         *   exponent2         INTEGER,  -- d mod (q-1)
         *   coefficient       INTEGER,  -- (inverse of q) mod p
         *   otherPrimeInfos   OtherPrimeInfos OPTIONAL.
         * }
         */
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();
        privateKey = new PrivateKeyInfo(ALGID_RSA,
            new RSAPrivateKey(priv.getModulus(),
                    priv.getPublicExponent(), priv.getPrivateExponent(),
                    priv.getPrimeP(), priv.getPrimeQ(),
                    priv.getPrimeExponentP(), priv.getPrimeExponentQ(),
                    priv.getCrtCoefficient()));
          break;
      }
      case "EC": {
        ASN1ObjectIdentifier curveOid = new ASN1ObjectIdentifier(tokens[1]);
        AlgorithmIdentifier keyAlgId =
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curveOid);

        KeyPair kp = KeyUtil.generateECKeypair(curveOid, random);
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        int orderBitLength = pub.getParams().getOrder().bitLength();

        byte[] keyData = KeyUtil.getUncompressedEncodedECPoint(pub.getW(), orderBitLength);
        publicKeyInfo = new SubjectPublicKeyInfo(keyAlgId, keyData);

        /*
         * ECPrivateKey ::= SEQUENCE {
         *   Version INTEGER { ecPrivkeyVer1(1) }
         *                   (ecPrivkeyVer1),
         *   privateKey      OCTET STRING,
         *   parameters [0]  Parameters OPTIONAL,
         *   publicKey  [1]  BIT STRING OPTIONAL
         * }
         *
         * Since the EC domain parameters are placed in the PKCS #8’s privateKeyAlgorithm field,
         * the optional parameters field in an ECPrivateKey must be omitted. A Cryptoki
         * application must be able to unwrap an ECPrivateKey that contains the optional publicKey
         * field; however, what is done with this publicKey field is outside the scope of
         * Cryptoki.
         */
         ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
         privateKey = new PrivateKeyInfo(keyAlgId,
                 new org.bouncycastle.asn1.sec.ECPrivateKey(orderBitLength, priv.getS()));
          break;
      }
      case "DSA": {
        int pLength = Integer.parseInt(tokens[1]);
        int qLength = Integer.parseInt(tokens[2]);
        DSAParameterSpec spec = DSAParameterCache.getDSAParameterSpec(pLength, qLength, null);
        KeyPair kp = KeyUtil.generateDSAKeypair(spec, random);
        DSAParameter parameter = new DSAParameter(spec.getP(), spec.getQ(), spec.getG());
        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, parameter);
        publicKeyInfo = new SubjectPublicKeyInfo(algId,
                new ASN1Integer(((DSAPublicKey) kp.getPublic()).getY()));

        // DSA private keys are represented as BER-encoded ASN.1 type INTEGER.
        DSAPrivateKey priv = (DSAPrivateKey) kp.getPrivate();
        privateKey = new PrivateKeyInfo(publicKeyInfo.getAlgorithm(), new ASN1Integer(priv.getX()));
        break;
      }
      case "ED25519":
      case "ED448":
      case "X25519":
      case "X448": {
        ASN1ObjectIdentifier curveId = EdECConstants.getCurveOid(keyspec);
        KeyPair kp = KeyUtil.generateEdECKeypair(curveId, random);
        publicKeyInfo = KeyUtil.createSubjectPublicKeyInfo(kp.getPublic());
        // make sure that the algorithm match
        if (!curveId.equals(publicKeyInfo.getAlgorithm().getAlgorithm())) {
          throw new XiSecurityException("invalid SubjectPublicKeyInfo.algorithm");
        }
        privateKey = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
          break;
      }
      default: {
        throw new IllegalArgumentException("unknown keyspec " + keyspec);
      }
    }

    return new KeypairGenResult(privateKey, publicKeyInfo);
  }

  @Override
  public boolean isHealthy() {
    return true;
  }

  @Override
  public void close() throws IOException {
  }

}
