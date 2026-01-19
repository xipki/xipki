// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

import org.xipki.pkcs11.wrapper.KeyPairTemplate;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.Template;

import java.util.Objects;

/**
 * @author Lijun Liao (xipki)
 */
public class PKCS11KeyPairSpec extends PKCS11KeySpec {

  private PKCS11KeyPairType keyPairType;

  private Boolean signRecover;

  private Boolean verifyRecover;

  private String publicKeyLabel;

  protected Boolean decapsulate;

  protected Boolean encapsulate;

  protected PKCS11TemplateSpec encapsulateTemplate;

  protected PKCS11TemplateSpec decapsulateTemplate;

  public PKCS11KeyPairSpec decryptEncrypt(Boolean decryptEncrypt) {
    return decryptEncrypt(decryptEncrypt, decryptEncrypt);
  }

  public PKCS11KeyPairSpec decryptEncrypt(Boolean decrypt, Boolean encrypt) {
    assertChangeable();
    this.decrypt = decrypt;
    this.encrypt = encrypt;
    return this;
  }

  public PKCS11KeyPairSpec decrypt(Boolean decrypt) {
    assertChangeable();
    this.decrypt = decrypt;
    return this;
  }

  public PKCS11KeyPairSpec encrypt(Boolean encrypt) {
    assertChangeable();
    this.encrypt = encrypt;
    return this;
  }

  public PKCS11KeyPairSpec derive(Boolean derive) {
    assertChangeable();
    this.derive = derive;
    return this;
  }

  public PKCS11KeyPairSpec deriveTemplate(PKCS11TemplateSpec deriveTemplate) {
    assertChangeable();
    this.deriveTemplate = deriveTemplate;
    return this;
  }

  public PKCS11KeyPairSpec encapsulateTemplate(
      PKCS11TemplateSpec encapsulateTemplate) {
    assertChangeable();
    this.encapsulateTemplate = encapsulateTemplate;
    return this;
  }

  public PKCS11KeyPairSpec decapsulateTemplate(
      PKCS11TemplateSpec decapsulateTemplate) {
    assertChangeable();
    this.decapsulateTemplate = decapsulateTemplate;
    return this;
  }

  public PKCS11KeyPairSpec extractable(Boolean extractable) {
    assertChangeable();
    this.extractable = extractable;
    return this;
  }

  public PKCS11KeyPairSpec generateId(boolean generateId) {
    assertChangeable();
    this.generateId = generateId;
    return this;
  }

  public PKCS11KeyPairSpec id(byte[] id) {
    assertChangeable();
    this.id = id;
    return this;
  }

  public PKCS11KeyPairType keyPairType() {
    return keyPairType;
  }

  public PKCS11KeyPairSpec keyPairType(PKCS11KeyPairType keyPairType) {
    assertChangeable();
    this.keyPairType = keyPairType;
    return this;
  }

  public PKCS11KeyPairSpec label(String label) {
    return labels(label, null);
  }

  public PKCS11KeyPairSpec labels(String label, String publicKeyLabel) {
    assertChangeable();
    this.label = label;
    this.publicKeyLabel = Objects.equals(label, publicKeyLabel)
        ? null : publicKeyLabel;
    return this;
  }

  public String publicKeyLabel() {
    return publicKeyLabel;
  }

  public String labelForPublicKey() {
    return publicKeyLabel != null ? publicKeyLabel : label;
  }

  public PKCS11KeyPairSpec modifiable(Boolean modifiable) {
    assertChangeable();
    this.modifiable = modifiable;
    return this;
  }

  public PKCS11KeyPairSpec private_(Boolean private_) {
    assertChangeable();
    this.private_ = private_;
    return this;
  }

  public PKCS11KeyPairSpec sensitive(Boolean sensitive) {
    assertChangeable();
    this.sensitive = sensitive;
    return this;
  }

  public PKCS11KeyPairSpec signVerify(Boolean signVerify) {
    return signVerify(signVerify, signVerify);
  }

  public PKCS11KeyPairSpec signVerify(Boolean sign, Boolean verify) {
    assertChangeable();
    this.sign = sign;
    this.verify = verify;
    return this;
  }

  public PKCS11KeyPairSpec sign(Boolean sign) {
    assertChangeable();
    this.sign = sign;
    return this;
  }

  public PKCS11KeyPairSpec verify(Boolean verify) {
    assertChangeable();
    this.verify = verify;
    return this;
  }

  public PKCS11KeyPairSpec signVerifyRecover(Boolean signVerifyRecover) {
    return signVerifyRecover(signVerifyRecover, signVerifyRecover);
  }

  public PKCS11KeyPairSpec signVerifyRecover(
      Boolean signRecover, Boolean verifyRecover) {
    assertChangeable();
    this.signRecover = signRecover;
    this.verifyRecover = verifyRecover;
    return this;
  }

  public PKCS11KeyPairSpec signRecover(Boolean signRecover) {
    assertChangeable();
    this.signRecover = signRecover;
    return this;
  }

  public PKCS11KeyPairSpec verifyRecover(Boolean verifyRecover) {
    assertChangeable();
    this.verifyRecover = verifyRecover;
    return this;
  }

  public PKCS11KeyPairSpec token(Boolean token) {
    assertChangeable();
    this.token = token;
    return this;
  }

  public PKCS11KeyPairSpec trusted(Boolean trusted) {
    assertChangeable();
    this.trusted = trusted;
    return this;
  }

  public PKCS11KeyPairSpec unwrapWrap(Boolean unwrapWrap) {
    return unwrapWrap(unwrapWrap, unwrapWrap);
  }

  public PKCS11KeyPairSpec unwrapWrap(Boolean unwrap, Boolean wrap) {
    assertChangeable();
    this.unwrap = unwrap;
    this.wrap = wrap;
    return this;
  }

  public PKCS11KeyPairSpec wrap(Boolean wrap) {
    assertChangeable();
    this.wrap = wrap;
    return this;
  }

  public PKCS11KeyPairSpec unwrap(Boolean unwrap) {
    assertChangeable();
    this.unwrap = unwrap;
    return this;
  }

  public PKCS11KeyPairSpec unwrapTemplate(PKCS11TemplateSpec unwrapTemplate) {
    assertChangeable();
    this.unwrapTemplate = unwrapTemplate;
    return this;
  }

  public PKCS11KeyPairSpec wrapTemplate(PKCS11TemplateSpec wrapTemplate) {
    assertChangeable();
    this.wrapTemplate = wrapTemplate;
    return this;
  }

  public PKCS11KeyPairSpec wrapWithTrusted(Boolean wrapWithTrusted) {
    assertChangeable();
    this.wrapWithTrusted = wrapWithTrusted;
    return this;
  }

  public PKCS11KeyPairSpec deEncapsulate(Boolean deEncapsulate) {
    return deEncapsulate(deEncapsulate, deEncapsulate);
  }

  public PKCS11KeyPairSpec deEncapsulate(
      Boolean encapsulate, Boolean decapsulate) {
    assertChangeable();
    this.encapsulate = encapsulate;
    this.decapsulate = decapsulate;
    return this;
  }

  public PKCS11KeyPairSpec encapsulate(Boolean encapsulate) {
    assertChangeable();
    this.encapsulate = encapsulate;
    return this;
  }

  public PKCS11KeyPairSpec decapsulate(Boolean decapsulate) {
    assertChangeable();
    this.decapsulate = decapsulate;
    return this;
  }

  public Boolean decapsulate() {
    return decapsulate;
  }

  public PKCS11TemplateSpec decapsulateTemplate() {
    return decapsulateTemplate;
  }

  public PKCS11TemplateSpec encapsulateTemplate() {
    return encapsulateTemplate;
  }

  public Boolean encapsulate() {
    return encapsulate;
  }

  public KeyPairTemplate toKeyPairTemplate() {
    return new KeyPairTemplate(toPrivateKeyAttributeVector(),
        toPublicKeyAttributeVector());
  }

  public Template toPrivateKeyAttributeVector() {
    Template ret = new Template()
        .class_(PKCS11T.CKO_PRIVATE_KEY)
        .decrypt(decrypt)
        .derive(derive)
        .extractable(extractable)
        .id(id)
        .label(label)
        .private_(private_)
        .modifiable(modifiable)
        .sensitive(sensitive)
        .sign(sign)
        .signRecover(signRecover)
        .token(token)
        .trusted(trusted)
        .unwrap(unwrap)
        .decapsulate(decapsulate)
        .wrapWithTrusted(wrapWithTrusted);

    if (keyPairType != null) {
      keyPairType.fillPrivateKey(ret);
    }

    if (deriveTemplate != null) {
      ret.deriveTemplate(deriveTemplate.toAttributeVector());
    }

    if (unwrapTemplate != null) {
      ret.unwrapTemplate(unwrapTemplate.toAttributeVector());
    }

    if (decapsulateTemplate != null) {
      ret.decapsulateTemplate(decapsulateTemplate.toAttributeVector());
    }

    return ret;
  }

  public Template toPublicKeyAttributeVector() {
    Template ret = new Template()
        .class_(PKCS11T.CKO_PUBLIC_KEY)
        .encrypt(encrypt)
        .id(id)
        .label(publicKeyLabel != null ? publicKeyLabel : label)
        .modifiable(modifiable)
        .token(token)
        .trusted(trusted)
        .wrap(wrap)
        .verify(verify)
        .verify(verifyRecover)
        .encapsulate(encapsulate);

    if (keyPairType != null) {
      keyPairType.fillPublicKey(ret);
    }

    if (wrapTemplate != null) {
      ret.wrapTemplate(wrapTemplate.toAttributeVector());
    }

    if (encapsulateTemplate != null) {
      ret.encapsulateTemplate(encapsulateTemplate.toAttributeVector());
    }

    return ret;
  }

  public boolean canGenerate(PKCS11Token token) {
    return keyPairType != null
        && token.canGenerateKeyPair(keyPairType);
  }

  public PKCS11KeyPairSpec unchangeableCopy() {
    PKCS11KeyPairSpec copy = copy();
    copy.setUnchangeable();
    return copy;
  }

  public PKCS11KeyPairSpec copy() {
    return new PKCS11KeyPairSpec()
        .decryptEncrypt(decrypt, encrypt).derive(derive)
        .deriveTemplate(deriveTemplate).extractable(extractable)
        .generateId(generateId).id(id).keyPairType(keyPairType)
        .labels(label, publicKeyLabel).modifiable(modifiable).private_(private_)
        .sensitive(sensitive).signVerify(sign, verify).token(token)
        .trusted(trusted).unwrapWrap(unwrap, wrap)
        .unwrapTemplate(unwrapTemplate)
        .signVerifyRecover(signRecover, verifyRecover)
        .wrapTemplate(wrapTemplate).wrapWithTrusted(wrapWithTrusted);
  }

  @Override
  public String toString() {
    return toString(true, "");
  }

  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder();
    if (withName) {
      sb.append(indent).append("PKCS11KeyPairSpec:");
      indent += "  ";
    }

    appendElement(sb, indent, "decrypt", decrypt);
    appendElement(sb, indent, "derive", derive);
    appendElement(sb, indent, "deriveTemplate", deriveTemplate);
    appendElement(sb, indent, "encrypt", encrypt);
    appendElement(sb, indent, "extractable", extractable);
    appendElement(sb, indent, "id", id);
    appendElement(sb, indent, "keyPairType", keyPairType);
    appendElement(sb, indent, "label", label);
    appendElement(sb, indent, "modifiable", modifiable);
    appendElement(sb, indent, "private", private_);
    appendElement(sb, indent, "publicKeyLabel", publicKeyLabel);
    appendElement(sb, indent, "sensitive", sensitive);
    appendElement(sb, indent, "sign", sign);
    appendElement(sb, indent, "signRecover", signRecover);
    appendElement(sb, indent, "token", token);
    appendElement(sb, indent, "trusted", trusted);
    appendElement(sb, indent, "unwrap", unwrap);
    appendElement(sb, indent, "unwrapTemplate", unwrapTemplate);
    appendElement(sb, indent, "verify", verify);
    appendElement(sb, indent, "verifyRecover", verifyRecover);
    appendElement(sb, indent, "wrap", wrap);
    appendElement(sb, indent, "wrapTemplate", wrapTemplate);
    appendElement(sb, indent, "wrapWithTrusted", wrapWithTrusted);
    return sb.toString();
  }

}
