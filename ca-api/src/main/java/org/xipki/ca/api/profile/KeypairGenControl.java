// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xipki.security.EdECConstants;
import org.xipki.util.Args;

/**
 * Control of how the CA generate keypair for the new certificate.
 *
 * @author Lijun Liao (xipki)
 *
 */

public abstract class KeypairGenControl {

  protected String keyspec;

  public ASN1ObjectIdentifier getKeyAlgorithmOid() {
    return null;
  }

  public final String getKeyspec() {
    return keyspec;
  }

  public static class ForbiddenKeypairGenControl extends KeypairGenControl {
    public static final ForbiddenKeypairGenControl INSTANCE = new ForbiddenKeypairGenControl();

    private ForbiddenKeypairGenControl() {
    }
  }

  public static class InheritCAKeypairGenControl extends KeypairGenControl {
    public static final InheritCAKeypairGenControl INSTANCE = new InheritCAKeypairGenControl();

    private InheritCAKeypairGenControl() {
    }
  } // class InheritCAKeypairGenControl

  public static class RSAKeypairGenControl extends KeypairGenControl {

    private final int keysize;

    private final AlgorithmIdentifier keyAlgorithm;

    public RSAKeypairGenControl(int keysize) {
      this(keysize, null);
    }

    public RSAKeypairGenControl(int keysize, ASN1ObjectIdentifier keyAlgorithmOid) {
      if (keysize < 1024 || keysize % 512 != 0) {
        throw new IllegalArgumentException("invalid keysize " + keysize);
      }

      this.keysize = keysize;
      this.keyAlgorithm = new AlgorithmIdentifier((keyAlgorithmOid != null)
          ? keyAlgorithmOid : PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

      this.keyspec = "RSA/" + keysize;
    } // constructor

    public int getKeysize() {
      return keysize;
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

    @Override
    public ASN1ObjectIdentifier getKeyAlgorithmOid() {
      return keyAlgorithm.getAlgorithm();
    }
  } // class RSAKeypairGenControl

  public static class ECKeypairGenControl extends KeypairGenControl {

    private final ASN1ObjectIdentifier curveOid;

    private final AlgorithmIdentifier keyAlgorithm;

    public ECKeypairGenControl(ASN1ObjectIdentifier curveOid) {
      this(curveOid, null);
    }

    public ECKeypairGenControl(ASN1ObjectIdentifier curveOid,
        ASN1ObjectIdentifier keyAlgorithmOid) {
      this.curveOid = Args.notNull(curveOid, "curveOid");
      this.keyAlgorithm = new AlgorithmIdentifier((keyAlgorithmOid != null)
          ? keyAlgorithmOid : X9ObjectIdentifiers.id_ecPublicKey, curveOid);
      keyspec = "EC/" + curveOid.getId();
    }

    public ASN1ObjectIdentifier getCurveOid() {
      return curveOid;
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

    @Override
    public ASN1ObjectIdentifier getKeyAlgorithmOid() {
      return keyAlgorithm.getAlgorithm();
    }

  } // class ECKeypairGenControl

  public static class DSAKeypairGenControl extends KeypairGenControl {

    private final int plength;

    private final int qlength;

    private final ASN1ObjectIdentifier keyAlgorithmOid;

    public DSAKeypairGenControl(int pLength) {
      this(pLength, 0, null);
    }

    public DSAKeypairGenControl(int pLength, int qLength, ASN1ObjectIdentifier keyAlgorithmOid) {
      if (pLength < 1024 || pLength % 1024 != 0) {
        throw new IllegalArgumentException("invalid pLength " + pLength);
      }

      if (qLength == 0) {
        qLength = pLength < 2048 ? 160 : pLength < 3072 ? 224 : 256;
      }

      this.plength = pLength;
      this.qlength = qLength;
      this.keyAlgorithmOid = (keyAlgorithmOid != null) ? keyAlgorithmOid : X9ObjectIdentifiers.id_dsa;
      keyspec = "DSA/" + pLength + "/" + qLength;
    }

    public int getPlength() {
      return plength;
    }

    public int getQlength() {
      return qlength;
    }

    @Override
    public ASN1ObjectIdentifier getKeyAlgorithmOid() {
      return keyAlgorithmOid;
    }

  } // class DSAKeypairGenControl

  public static class EDDSAKeypairGenControl extends KeypairGenControl {

    private final AlgorithmIdentifier keyAlgorithm;

    public EDDSAKeypairGenControl(ASN1ObjectIdentifier keyAlgorithmOid) {
      this.keyAlgorithm = new AlgorithmIdentifier(Args.notNull(keyAlgorithmOid, "keyAlgorithmOid"));
      this.keyspec = EdECConstants.getName(keyAlgorithmOid);
      if (this.keyspec == null) {
        throw new IllegalArgumentException("invalid EdDSA keyAlgorithmOid " + keyAlgorithmOid.getId());
      }
    }

    public AlgorithmIdentifier getKeyAlgorithm() {
      return keyAlgorithm;
    }

    @Override
    public ASN1ObjectIdentifier getKeyAlgorithmOid() {
      return keyAlgorithm.getAlgorithm();
    }

  } // class EDDSAKeypairGenControl

}
