// Copyright (c) 2025 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.Template;

/**
 * @author Lijun Liao (xipki)
 */
public class PKCS11SecretKeySpec extends PKCS11KeySpec {

  private Long keyType;

  private Integer valueLen;

  public Long keyType() {
    return keyType;
  }

  public Integer valueLen() {
    return valueLen;
  }

  public PKCS11SecretKeySpec valueLen(Integer valueLen) {
    this.valueLen = valueLen;
    return this;
  }

  public PKCS11SecretKeySpec decrypt(Boolean decrypt) {
    assertChangeable();
    this.decrypt = decrypt;
    return this;
  }

  public PKCS11SecretKeySpec derive(Boolean derive) {
    assertChangeable();
    this.derive = derive;
    return this;
  }

  public PKCS11SecretKeySpec deriveTemplate(PKCS11TemplateSpec deriveTemplate) {
    assertChangeable();
    this.deriveTemplate = deriveTemplate;
    return this;
  }

  public PKCS11SecretKeySpec encrypt(Boolean encrypt) {
    assertChangeable();
    this.encrypt = encrypt;
    return this;
  }

  public PKCS11SecretKeySpec extractable(Boolean extractable) {
    assertChangeable();
    this.extractable = extractable;
    return this;
  }

  public PKCS11SecretKeySpec generateId(boolean generateId) {
    assertChangeable();
    this.generateId = generateId;
    return this;
  }

  public PKCS11SecretKeySpec id(byte[] id) {
    assertChangeable();
    this.id = id;
    return this;
  }

  public PKCS11SecretKeySpec keyType(Long keyType) {
    assertChangeable();
    this.keyType = keyType;
    return this;
  }

  public PKCS11SecretKeySpec label(String label) {
    assertChangeable();
    this.label = label;
    return this;
  }

  public PKCS11SecretKeySpec modifiable(Boolean modifiable) {
    assertChangeable();
    this.modifiable = modifiable;
    return this;
  }

  public PKCS11SecretKeySpec private_(Boolean private_) {
    assertChangeable();
    this.private_ = private_;
    return this;
  }

  public PKCS11SecretKeySpec sensitive(Boolean sensitive) {
    assertChangeable();
    this.sensitive = sensitive;
    return this;
  }

  public PKCS11SecretKeySpec sign(Boolean sign) {
    assertChangeable();
    this.sign = sign;
    return this;
  }

  public PKCS11SecretKeySpec token(Boolean token) {
    assertChangeable();
    this.token = token;
    return this;
  }

  public PKCS11SecretKeySpec trusted(Boolean trusted) {
    assertChangeable();
    this.trusted = trusted;
    return this;
  }

  public PKCS11SecretKeySpec unwrap(Boolean unwrap) {
    assertChangeable();
    this.unwrap = unwrap;
    return this;
  }

  public PKCS11SecretKeySpec unwrapTemplate(PKCS11TemplateSpec unwrapTemplate) {
    assertChangeable();
    this.unwrapTemplate = unwrapTemplate;
    return this;
  }

  public PKCS11SecretKeySpec verify(Boolean verify) {
    assertChangeable();
    this.verify = verify;
    return this;
  }

  public PKCS11SecretKeySpec wrap(Boolean wrap) {
    assertChangeable();
    this.wrap = wrap;
    return this;
  }

  public PKCS11SecretKeySpec wrapTemplate(PKCS11TemplateSpec wrapTemplate) {
    assertChangeable();
    this.wrapTemplate = wrapTemplate;
    return this;
  }

  public PKCS11SecretKeySpec wrapWithTrusted(Boolean wrapWithTrusted) {
    assertChangeable();
    this.wrapWithTrusted = wrapWithTrusted;
    return this;
  }

  public boolean canGenerate(PKCS11Token token) {
    return keyType != null && token.canGenerateKey(keyType);
  }

  public Template toTemplate() {
    Template ret = new Template()
        .class_(PKCS11T.CKO_SECRET_KEY).decrypt(decrypt).derive(derive)
        .encrypt(encrypt).extractable(extractable).id(id).keyType(keyType)
        .label(label).private_(private_).modifiable(modifiable)
        .sensitive(sensitive).sign(sign).token(token).trusted(trusted)
        .wrap(wrap).unwrap(unwrap).valueLen(valueLen).verify(verify)
        .wrapWithTrusted(wrapWithTrusted);

    if (deriveTemplate != null) {
      ret.deriveTemplate(deriveTemplate.toAttributeVector());
    }

    if (unwrapTemplate != null) {
      ret.unwrapTemplate(unwrapTemplate.toAttributeVector());
    }

    if (wrapTemplate != null) {
      ret.wrapTemplate(wrapTemplate.toAttributeVector());
    }

    return ret;
  }

  public PKCS11SecretKeySpec unchangeableCopy() {
    PKCS11SecretKeySpec copy = copy();
    copy.setUnchangeable();
    return copy;
  }

  public PKCS11SecretKeySpec copy() {
    return new PKCS11SecretKeySpec()
        .decrypt(decrypt).derive(derive).encrypt(encrypt)
        .extractable(extractable).generateId(generateId).id(id).keyType(keyType)
        .label(label).private_(private_).modifiable(modifiable)
        .sensitive(sensitive).sign(sign).token(token).trusted(trusted)
        .wrap(wrap).unwrap(unwrap).valueLen(valueLen).verify(verify)
        .wrapWithTrusted(wrapWithTrusted).deriveTemplate(deriveTemplate)
        .unwrapTemplate(unwrapTemplate).wrapTemplate(wrapTemplate);
  }

  @Override
  public String toString() {
    return toString(true, "");
  }

  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder();
    if (withName) {
      sb.append(indent).append("PKCS11SecretKeySpec:");
      indent += "  ";
    }

    appendElement(sb, indent, "decrypt", decrypt);
    appendElement(sb, indent, "derive", derive);
    appendElement(sb, indent, "deriveTemplate", deriveTemplate);
    appendElement(sb, indent, "encrypt", encrypt);
    appendElement(sb, indent, "extractable", extractable);
    appendElement(sb, indent, "generateId", generateId);
    appendElement(sb, indent, "id", id);
    appendElement(sb, indent, "keyType", keyType);
    appendElement(sb, indent, "label", label);
    appendElement(sb, indent, "modifiable", modifiable);
    appendElement(sb, indent, "private", private_);
    appendElement(sb, indent, "sensitive", sensitive);
    appendElement(sb, indent, "sign", sign);
    appendElement(sb, indent, "token", token);
    appendElement(sb, indent, "trusted", trusted);
    appendElement(sb, indent, "unwrap", unwrap);
    appendElement(sb, indent, "unwrapTemplate", unwrapTemplate);
    appendElement(sb, indent, "valueLen", valueLen);
    appendElement(sb, indent, "verify", verify);
    appendElement(sb, indent, "wrap", wrap);
    appendElement(sb, indent, "wrapTemplate", wrapTemplate);
    appendElement(sb, indent, "wrapWithTrusted", wrapWithTrusted);
    return sb.toString();
  }

}
