// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.wrapper.spec;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class PKCS11KeySpec extends PKCS11Spec {

  protected PKCS11TemplateSpec deriveTemplate;

  protected boolean generateId = true;

  protected byte[] id;

  protected String label;

  protected Boolean token;

  protected Boolean modifiable;

  protected Boolean private_;

  protected Boolean decrypt;

  protected Boolean derive;

  protected Boolean encrypt;

  protected Boolean extractable;

  protected Boolean sensitive;

  protected Boolean sign;

  protected Boolean trusted;

  protected Boolean unwrap;

  protected PKCS11TemplateSpec unwrapTemplate;

  protected Boolean verify;

  protected Boolean wrap;

  protected PKCS11TemplateSpec wrapTemplate;

  protected Boolean wrapWithTrusted;

  public Boolean decrypt() {
    return decrypt;
  }

  public Boolean derive() {
    return derive;
  }

  public PKCS11TemplateSpec deriveTemplate() {
    return deriveTemplate;
  }

  public Boolean encrypt() {
    return encrypt;
  }

  public Boolean extractable() {
    return extractable;
  }

  public boolean generateId() {
    return generateId;
  }

  public byte[] id() {
    return id;
  }

  public String label() {
    return label;
  }

  public Boolean modifiable() {
    return modifiable;
  }

  public Boolean private_() {
    return private_;
  }

  public Boolean sensitive() {
    return sensitive;
  }

  public Boolean sign() {
    return sign;
  }

  public Boolean token() {
    return token;
  }

  public Boolean trusted() {
    return trusted;
  }

  public Boolean unwrap() {
    return unwrap;
  }

  public PKCS11TemplateSpec unwrapTemplate() {
    return unwrapTemplate;
  }

  public Boolean verify() {
    return verify;
  }

  public Boolean wrap() {
    return wrap;
  }

  public PKCS11TemplateSpec wrapTemplate() {
    return wrapTemplate;
  }

  public Boolean wrapWithTrusted() {
    return wrapWithTrusted;
  }

}
