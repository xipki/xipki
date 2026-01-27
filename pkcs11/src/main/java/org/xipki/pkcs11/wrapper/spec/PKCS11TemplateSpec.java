// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

import org.xipki.pkcs11.wrapper.attrs.Template;

/**
 * @author Lijun Liao (xipki)
 */
public class PKCS11TemplateSpec extends PKCS11Spec {

  private Boolean decrypt;

  private Boolean derive;

  private Boolean encrypt;

  private Boolean extractable;

  private Long keyType;

  private Boolean private_;

  private Boolean sensitive;

  private Boolean sign;

  private Boolean signRecover;

  private Boolean trusted;

  private Boolean unwrap;

  private Boolean verify;

  private Boolean verifyRecover;

  private Boolean wrap;

  private Boolean wrapWithTrusted;

  public Boolean decrypt() {
    return decrypt;
  }

  public PKCS11TemplateSpec decrypt(Boolean decrypt) {
    assertChangeable();
    this.decrypt = decrypt;
    return this;
  }

  public Boolean derive() {
    return derive;
  }

  public PKCS11TemplateSpec derive(Boolean derive) {
    assertChangeable();
    this.derive = derive;
    return this;
  }

  public Boolean encrypt() {
    return encrypt;
  }

  public PKCS11TemplateSpec encrypt(Boolean encrypt) {
    assertChangeable();
    this.encrypt = encrypt;
    return this;
  }

  public Boolean extractable() {
    return extractable;
  }

  public PKCS11TemplateSpec extractable(Boolean extractable) {
    assertChangeable();
    this.extractable = extractable;
    return this;
  }

  public Long keyType() {
    return keyType;
  }

  public PKCS11TemplateSpec keyType(Long keyType) {
    assertChangeable();
    this.keyType = keyType;
    return this;
  }

  public Boolean private_() {
    return private_;
  }

  public PKCS11TemplateSpec private_(Boolean private_) {
    assertChangeable();
    this.private_ = private_;
    return this;
  }

  public Boolean sensitive() {
    return sensitive;
  }

  public PKCS11TemplateSpec sensitive(Boolean sensitive) {
    assertChangeable();
    this.sensitive = sensitive;
    return this;
  }

  public Boolean sign() {
    return sign;
  }

  public PKCS11TemplateSpec sign(Boolean sign) {
    assertChangeable();
    this.sign = sign;
    return this;
  }

  public Boolean signRecover() {
    return signRecover;
  }

  public PKCS11TemplateSpec signRecover(Boolean signRecover) {
    assertChangeable();
    this.signRecover = signRecover;
    return this;
  }

  public Boolean trusted() {
    return trusted;
  }

  public PKCS11TemplateSpec trusted(Boolean trusted) {
    assertChangeable();
    this.trusted = trusted;
    return this;
  }

  public Boolean unwrap() {
    return unwrap;
  }

  public PKCS11TemplateSpec unwrap(Boolean unwrap) {
    assertChangeable();
    this.unwrap = unwrap;
    return this;
  }

  public Boolean verify() {
    return verify;
  }

  public PKCS11TemplateSpec verify(Boolean verify) {
    assertChangeable();
    this.verify = verify;
    return this;
  }

  public Boolean verifyRecover() {
    return verifyRecover;
  }

  public PKCS11TemplateSpec verifyRecover(Boolean verifyRecover) {
    assertChangeable();
    this.verifyRecover = verifyRecover;
    return this;
  }

  public Boolean wrap() {
    return wrap;
  }

  public PKCS11TemplateSpec wrap(Boolean wrap) {
    assertChangeable();
    this.wrap = wrap;
    return this;
  }

  public Boolean wrapWithTrusted() {
    return wrapWithTrusted;
  }

  public PKCS11TemplateSpec wrapWithTrusted(Boolean wrapWithTrusted) {
    assertChangeable();
    this.wrapWithTrusted = wrapWithTrusted;
    return this;
  }

  public Template toAttributeVector() {
    return new Template().decrypt(decrypt).derive(derive).encrypt(encrypt)
        .extractable(extractable).keyType(keyType).private_(private_)
        .sensitive(sensitive).sign(sign).signRecover(signRecover)
        .trusted(trusted).wrap(wrap).unwrap(unwrap).verify(verify)
        .verifyRecover(verifyRecover).wrapWithTrusted(wrapWithTrusted);
  }

  public PKCS11TemplateSpec unchangeableCopy() {
    PKCS11TemplateSpec copy = copy();
    copy.setUnchangeable();
    return copy;
  }

  public PKCS11TemplateSpec copy() {
    return new PKCS11TemplateSpec().decrypt(decrypt).derive(derive)
        .encrypt(encrypt).extractable(extractable).keyType(keyType)
        .private_(private_).sensitive(sensitive).sign(sign)
        .signRecover(signRecover).trusted(trusted).unwrap(unwrap).verify(verify)
        .verifyRecover(verifyRecover).wrapWithTrusted(wrapWithTrusted);
  }

  @Override
  public String toString() {
    return toString(true, "");
  }

  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder();
    if (withName) {
      sb.append(indent).append("PKCS11TemplateSpec:");
      indent += "  ";
    }

    appendElement(sb, indent, "decrypt", decrypt);
    appendElement(sb, indent, "derive", derive);
    appendElement(sb, indent, "encrypt", encrypt);
    appendElement(sb, indent, "extractable", extractable);
    appendElement(sb, indent, "keyType", keyType);
    appendElement(sb, indent, "private", private_);
    appendElement(sb, indent, "sensitive", sensitive);
    appendElement(sb, indent, "sign", sign);
    appendElement(sb, indent, "signRecover", signRecover);
    appendElement(sb, indent, "trusted", trusted);
    appendElement(sb, indent, "unwrap", unwrap);
    appendElement(sb, indent, "verify", verify);
    appendElement(sb, indent, "verifyRecover", verifyRecover);
    appendElement(sb, indent, "wrap", wrap);
    appendElement(sb, indent, "wrapWithTrusted", wrapWithTrusted);
    return sb.toString();
  }

  public static PKCS11TemplateSpec from(Template vec) {
    return new PKCS11TemplateSpec().decrypt(vec.decrypt()).derive(vec.derive())
        .encrypt(vec.encrypt()).extractable(vec.extractable())
        .keyType(vec.keyType()).private_(vec.private_())
        .sensitive(vec.sensitive()).sign(vec.sign())
        .signRecover(vec.signRecover()).trusted(vec.trusted()).wrap(vec.wrap())
        .unwrap(vec.unwrap()).verify(vec.verify())
        .verifyRecover(vec.verifyRecover())
        .wrapWithTrusted(vec.wrapWithTrusted());
  }

}
