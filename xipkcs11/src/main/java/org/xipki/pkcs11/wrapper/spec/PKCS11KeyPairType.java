// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.util.codec.asn1.Asn1Util;

import static org.xipki.pkcs11.wrapper.spec.PKCS11Spec.appendElement;

/**
 * @author Lijun Liao (xipki)
 */
public interface PKCS11KeyPairType {

  ECMontgomery X25519 = new ECMontgomery("1.3.101.110");

  ECMontgomery X448 = new ECMontgomery("1.3.101.111");

  ECEdwards ED25519 = new ECEdwards("1.3.101.112");

  ECEdwards ED448 = new ECEdwards("1.3.101.113");

  EC EC_P256 = new EC("1.2.840.10045.3.1.7");

  EC EC_P384 = new EC("1.3.132.0.34");

  EC EC_P521 = new EC("1.3.132.0.35");

  EC EC_BrainpoolP256R1 = new EC("1.3.36.3.3.2.8.1.1.7");

  EC EC_BrainpoolP384R1 = new EC("1.3.36.3.3.2.8.1.1.11");

  EC EC_BrainpoolP512R1 = new EC("1.3.36.3.3.2.8.1.1.13");

  EC EC_FRP256V1 = new EC("1.2.250.1.223.101.256.1");

  SM2 SM2 = new SM2();

  RSA RSA_1024 = new RSA(1024);

  RSA RSA_2048 = new RSA(2048);

  RSA RSA_3072 = new RSA(3072);

  RSA RSA_4096 = new RSA(4096);

  MLDSA MLDSA44 = new MLDSA(PKCS11T.CKP_ML_DSA_44);

  MLDSA MLDSA65 = new MLDSA(PKCS11T.CKP_ML_DSA_65);

  MLDSA MLDSA87 = new MLDSA(PKCS11T.CKP_ML_DSA_87);

  MLKEM MLKEM512 = new MLKEM(PKCS11T.CKP_ML_KEM_512);

  MLKEM MLKEM768 = new MLKEM(PKCS11T.CKP_ML_KEM_768);

  MLKEM MLKEM1024 = new MLKEM(PKCS11T.CKP_ML_KEM_1024);

  CkMechanism getGenerateMechanism();

  long getKeyType();

  void fillPrivateKey(Template template);

  void fillPublicKey(Template template);

  String toString(boolean withName, String indent);

  abstract class Base implements PKCS11KeyPairType {

    @Override
    public CkMechanism getGenerateMechanism(){
      return new CkMechanism(getGenerateCkm());
    }

    protected abstract long getGenerateCkm();

    @Override
    public void fillPrivateKey(Template template) {
      template.keyType(getKeyType());
      extraFillPrivateKey(template);
    }

    protected void extraFillPrivateKey(Template template) {
    }

    @Override
    public void fillPublicKey(Template template) {
      template.keyType(getKeyType());
      extraFillPublicKey(template);
    }

    protected abstract void extraFillPublicKey(Template template);
  }

  abstract class GenericEC extends Base {

    private final long ckm;

    private final long keyType;

    private final String curveOid;

    public String getCurveOid() {
      return curveOid;
    }

    public GenericEC(long ckm, long keyType, String curveOid) {
      this.ckm = ckm;
      this.keyType = keyType;
      this.curveOid = curveOid;
    }

    @Override
    public long getGenerateCkm() {
      return ckm;
    }

    @Override
    public long getKeyType() {
      return keyType;
    }

    @Override
    protected void extraFillPublicKey(Template template) {
      template.ecParams(Asn1Util.encodeOid(curveOid));
    }

    @Override
    public String toString() {
      return toString(true, "");
    }

    @Override
    public String toString(boolean withName, String indent) {
      String className = getClass().getSimpleName();
      StringBuilder sb = new StringBuilder();
      if (withName) {
        sb.append(indent).append("PKCS11KeyPairType.").append(className)
            .append(":");
        indent += "  ";
      }

      appendElement(sb, indent, "keyType",
          PKCS11T.ckkCodeToName(getKeyType()));
      appendElement(sb, indent, "Curve", curveOid);
      return sb.toString();
    }

  }

  class EC extends GenericEC {
    public EC(String curveOid) {
      super(PKCS11T.CKM_EC_KEY_PAIR_GEN,
          PKCS11T.CKK_EC, curveOid);
    }
  }

  class ECEdwards extends GenericEC {
    public ECEdwards(String curveOid) {
      super(PKCS11T.CKM_EC_EDWARDS_KEY_PAIR_GEN,
          PKCS11T.CKK_EC_EDWARDS, curveOid);
    }
  }

  class ECMontgomery extends GenericEC {
    public ECMontgomery(String curveOid) {
      super(PKCS11T.CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
          PKCS11T.CKK_EC_MONTGOMERY, curveOid);
    }
  }

  class MLDSA extends Base {

    private final long variant;

    public MLDSA(long variant) {
      this.variant = variant;
    }

    public long getVariant() {
      return variant;
    }

    @Override
    public long getGenerateCkm() {
      return PKCS11T.CKM_ML_DSA_KEY_PAIR_GEN;
    }

    @Override
    public long getKeyType() {
      return PKCS11T.CKK_ML_DSA;
    }

    @Override
    protected void extraFillPublicKey(Template template) {
      template.parameterSet(variant);
    }

    @Override
    public String toString() {
      return toString(true, "");
    }

    @Override
    public String toString(boolean withName, String indent) {
      StringBuilder sb = new StringBuilder();
      if (withName) {
        sb.append(indent).append("PKCS11KeyPairType.MLDSA:");
        indent += "  ";
      }

      appendElement(sb, indent, "keyType",
          PKCS11T.ckkCodeToName(getKeyType()));
      appendElement(sb, indent, "variant", variant);
      return sb.toString();
    }

  }

  class MLKEM extends Base {

    private final long variant;

    public MLKEM(long variant) {
      this.variant = variant;
    }

    public long getVariant() {
      return variant;
    }

    @Override
    public long getGenerateCkm() {
      return PKCS11T.CKM_ML_KEM_KEY_PAIR_GEN;
    }

    @Override
    public long getKeyType() {
      return PKCS11T.CKK_ML_KEM;
    }

    @Override
    protected void extraFillPublicKey(Template template) {
      template.parameterSet(variant);
    }

    @Override
    public String toString() {
      return toString(true, "");
    }

    @Override
    public String toString(boolean withName, String indent) {
      StringBuilder sb = new StringBuilder();
      if (withName) {
        sb.append(indent).append("PKCS11KeyPairType.MLKEM:");
        indent += "  ";
      }

      appendElement(sb, indent, "keyType",
          PKCS11T.ckkCodeToName(getKeyType()));
      appendElement(sb, indent, "variant", variant);
      return sb.toString();
    }

  }

  class RSA extends Base {

    private final int modulusBits;

    public RSA(int modulusBits) {
      this.modulusBits = modulusBits;
    }

    @Override
    public long getGenerateCkm() {
      return PKCS11T.CKM_RSA_PKCS_KEY_PAIR_GEN;
    }

    @Override
    public long getKeyType() {
      return PKCS11T.CKK_RSA;
    }

    @Override
    public void extraFillPublicKey(Template template) {
      template.modulusBits(modulusBits);
    }

    public int getModulusBits() {
      return modulusBits;
    }

    @Override
    public String toString() {
      return toString(true, "");
    }

    @Override
    public String toString(boolean withName, String indent) {
      StringBuilder sb = new StringBuilder();
      if (withName) {
        sb.append(indent).append("PKCS11KeyPairType.RSA:");
        indent += "  ";
      }

      appendElement(sb, indent, "keyType",
          PKCS11T.ckkCodeToName(getKeyType()));
      appendElement(sb, indent, "ModulusBits", modulusBits);
      return sb.toString();
    }

  }

  class SM2 extends GenericEC {

    private SM2() {
      super(PKCS11T.CKM_VENDOR_SM2_KEY_PAIR_GEN,
          PKCS11T.CKK_VENDOR_SM2, "1.2.156.10197.1.301");
    }

    @Override
    public void extraFillPublicKey(Template template) {
    }

  }

}
