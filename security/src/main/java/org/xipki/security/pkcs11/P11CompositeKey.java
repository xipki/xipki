// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.KeySpec;
import org.xipki.security.composite.CompositeKemSuite;
import org.xipki.security.composite.CompositeSigSuite;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.security.PublicKey;

/**
 * PKCS#11 composite key.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11CompositeKey {

  public static final String COMPOSITE_LABEL_PREFIX = "COMPOSITE:";

  public static final String COMP_PQC_LABEL_PREFIX  = "COMP-PQC:";

  public static final String COMP_TRAD_LABEL_PREFIX = "COMP-TRAD:";

  private static final Logger LOG =
      LoggerFactory.getLogger(P11CompositeKey.class);

  private final P11Key pqcKey;

  private final P11Key tradKey;

  private final CompositeSigSuite sigAlgoSuite;

  private final CompositeKemSuite kemAlgoSuite;

  private boolean publicKeyInitialized;

  private PublicKey publicKey;

  public P11CompositeKey(P11Key pqcKey, P11Key tradKey,
                         CompositeSigSuite algoSuite) {
    this.pqcKey  = Args.notNull(pqcKey, "pqcKey");
    this.tradKey = Args.notNull(tradKey, "tradKey");

    KeySpec  pqcKeySpec =  pqcKey.getKeySpec();
    KeySpec tradKeySpec = tradKey.getKeySpec();
    if (algoSuite != null) {
      if (algoSuite.mldsaVariant().keySpec() != pqcKeySpec ||
          algoSuite. tradVariant().keySpec() != tradKeySpec) {
        throw new IllegalArgumentException("key and algoSuite do not match");
      }
    } else {
      if (pqcKeySpec == KeySpec.MLDSA44) {
        switch (tradKeySpec) {
          case RSA2048:
            algoSuite = CompositeSigSuite.MLDSA44_RSA2048_PSS_SHA256;
            break;
          case SECP256R1:
            algoSuite = CompositeSigSuite.MLDSA44_ECDSA_P256_SHA256;
            break;
          case ED25519:
            algoSuite = CompositeSigSuite.MLDSA44_Ed25519_SHA512;
            break;
        }
      } else if (pqcKeySpec == KeySpec.MLDSA65) {
        switch (tradKeySpec) {
          case RSA3072:
            algoSuite = CompositeSigSuite.MLDSA65_RSA3072_PSS_SHA512;
            break;
          case RSA4096:
            algoSuite = CompositeSigSuite.MLDSA65_RSA4096_PSS_SHA512;
            break;
          case BRAINPOOLP256R1:
            algoSuite = CompositeSigSuite.MLDSA65_ECDSA_BP256_SHA512;
            break;
          case SECP256R1:
            algoSuite = CompositeSigSuite.MLDSA65_ECDSA_P256_SHA512;
            break;
          case SECP384R1:
            algoSuite = CompositeSigSuite.MLDSA65_ECDSA_P384_SHA512;
            break;
          case ED25519:
            algoSuite = CompositeSigSuite.MLDSA65_Ed25519_SHA512;
            break;
        }
      } else if (pqcKeySpec == KeySpec.MLDSA87) {
        switch (tradKeySpec) {
           case RSA3072:
             algoSuite = CompositeSigSuite.MLDSA87_RSA3072_PSS_SHA512;
             break;
           case RSA4096:
             algoSuite = CompositeSigSuite.MLDSA87_RSA4096_PSS_SHA512;
             break;
           case BRAINPOOLP384R1:
             algoSuite = CompositeSigSuite.MLDSA87_ECDSA_BP384_SHA512;
             break;
           case SECP384R1:
             algoSuite = CompositeSigSuite.MLDSA87_ECDSA_P384_SHA512;
             break;
          case SECP521R1:
            algoSuite = CompositeSigSuite.MLDSA87_ECDSA_P521_SHA512;
            break;
          case ED25519:
            algoSuite = CompositeSigSuite.MLDSA87_Ed448_SHAKE256;
            break;
         }
      } else {
        throw new IllegalArgumentException("pqcKey is not an MLDSA key");
      }
    }

    this.sigAlgoSuite = algoSuite;
    this.kemAlgoSuite = null;

    if (!pqcKey.getSlotId().equals(tradKey.getSlotId())) {
      throw new IllegalArgumentException(
          "pqcKey and tradKey are not in the same slot");
    }
  }

  public P11CompositeKey(P11Key pqcKey, P11Key tradKey,
                         CompositeKemSuite algoSuite) {
    this.pqcKey  = Args.notNull(pqcKey, "pqcKey");
    this.tradKey = Args.notNull(tradKey, "tradKey");

    KeySpec  pqcKeySpec =  pqcKey.getKeySpec();
    KeySpec tradKeySpec = tradKey.getKeySpec();
    if (algoSuite != null) {
      if (algoSuite.mlkemVariant().keySpec() != pqcKeySpec ||
          algoSuite. tradVariant().keySpec() != tradKeySpec) {
        throw new IllegalArgumentException("key and algoSuite do not match");
      }
    } else {
      if (pqcKeySpec == KeySpec.MLKEM768) {
        switch (tradKeySpec) {
          case RSA2048:
            algoSuite = CompositeKemSuite.MLKEM768_RSA2048_SHA3_256;
            break;
          case RSA3072:
            algoSuite = CompositeKemSuite.MLKEM768_RSA3072_SHA3_256;
            break;
          case RSA4096:
            algoSuite = CompositeKemSuite.MLKEM768_RSA4096_SHA3_256;
            break;
          case SECP256R1:
            algoSuite = CompositeKemSuite.MLKEM768_ECDH_P256_SHA3_256;
            break;
          case SECP384R1:
            algoSuite = CompositeKemSuite.MLKEM768_ECDH_P384_SHA3_256;
            break;
          case BRAINPOOLP256R1:
            algoSuite =
                CompositeKemSuite.MLKEM768_ECDH_BRAINPOOLP256R1_SHA3_256;
            break;
          case X25519:
            algoSuite = CompositeKemSuite.MLKEM768_X25519_SHA3_256;
        }
      } else if (pqcKeySpec == KeySpec.MLKEM1024) {
        switch (tradKeySpec) {
          case RSA3072:
            algoSuite = CompositeKemSuite.MLKEM1024_RSA3072_SHA3_256;
            break;
          case SECP384R1:
            algoSuite = CompositeKemSuite.MLKEM1024_ECDH_P384_SHA3_256;
            break;
          case SECP521R1:
            algoSuite = CompositeKemSuite.MLKEM1024_ECDH_P521_SHA3_256;
            break;
          case BRAINPOOLP384R1:
            algoSuite =
                CompositeKemSuite.MLKEM1024_ECDH_BRAINPOOLP384R1_SHA3_256;
            break;
          case X448:
            algoSuite = CompositeKemSuite.MLKEM1024_X448_SHA3_256;
            break;
        }
      } else {
        throw new IllegalArgumentException("pqcKey is not an MLDSA key");
      }
    }

    this.kemAlgoSuite = algoSuite;
    this.sigAlgoSuite = null;

    if (!pqcKey.getSlotId().equals(tradKey.getSlotId())) {
      throw new IllegalArgumentException(
          "pqcKey and tradKey are not in the same slot");
    }
  }

  public static P11CompositeKey newCompositeSigKey(
      P11Key pqcKey, P11Key tradKey) {
    return new P11CompositeKey(pqcKey, tradKey, (CompositeKemSuite) null);
  }

  public static P11CompositeKey newCompositeKemKey(
      P11Key pqcKey, P11Key tradKey) {
    return new P11CompositeKey(pqcKey, tradKey, (CompositeKemSuite) null);
  }

  public P11Key pqcKey() {
    return pqcKey;
  }

  public P11Key tradKey() {
    return tradKey;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
    if (publicKey != null) {
      publicKeyInitialized = true;
    }
  }

  public void destroy() throws TokenException {
    pqcKey.destroy();
    tradKey.destroy();
  }

  public boolean isSign() {
    return pqcKey.isSign() && tradKey.isSign();
  }

  public boolean supportsSign(long pqcMechanism, long tradMechanism) {
    return pqcKey.supportsSign(pqcMechanism)
        && tradKey.supportsSign(tradMechanism);
  }

  public P11SlotId getSlotId() {
    return pqcKey.getSlotId();
  }

  public CompositeSigSuite getSigAlgoSuite() {
    return sigAlgoSuite;
  }

  public CompositeKemSuite getKemAlgoSuite() {
    return kemAlgoSuite;
  }

  public PublicKey getPublicKey() {
    if (publicKeyInitialized) {
      return publicKey;
    }

    try {
      this.publicKey = initPublicKey();
    } catch (Exception e) {
      LogUtil.error(LOG, e, "could not initialize composite public key " +
          "for (private) key (PQC: " + pqcKey.getKey().id() +
          ", trad: " + tradKey.getKey().id() + " on slot " + getSlotId());
    } finally {
      publicKeyInitialized = true;
    }

    return publicKey;
  }

  private PublicKey initPublicKey() throws IOException {
    PublicKey  pqcPublicKey =  pqcKey.getPublicKey();
    PublicKey tradPublicKey = tradKey.getPublicKey();

    byte[] pqc_pk = SubjectPublicKeyInfo.getInstance(
        pqcPublicKey.getEncoded()).getPublicKeyData().getOctets();
    byte[] trad_pk = SubjectPublicKeyInfo.getInstance(
        tradPublicKey.getEncoded()).getPublicKeyData().getOctets();

    byte[] pk = IoUtil.concatenate(pqc_pk, trad_pk);

    AlgorithmIdentifier algId = sigAlgoSuite != null
        ? sigAlgoSuite.algId() : kemAlgoSuite.algId();
    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, pk);
    return BouncyCastleProvider.getPublicKey(spki);
  }

}
