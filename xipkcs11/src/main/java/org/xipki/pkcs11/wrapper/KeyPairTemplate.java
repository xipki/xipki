// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.attrs.Template;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Template pair for the private key and public key.
 * @author Lijun Liao (xipki)
 */
public class KeyPairTemplate {

  private final Template privateKey;
  private final Template publicKey;

  public KeyPairTemplate() {
    this.privateKey = Template.newPrivateKey();
    this.publicKey = Template.newPublicKey();
  }

  public KeyPairTemplate(long keyType) {
    this.privateKey = Template.newPrivateKey(keyType);
    this.publicKey = Template.newPublicKey(keyType);
  }

  public KeyPairTemplate(Template privateKey,
                         Template publicKey) {
    this.privateKey = Objects.requireNonNull(
        privateKey, "privateKey must not be null");
    this.publicKey = Objects.requireNonNull(
        publicKey, "publicKey must not be null");
    if (!Objects.equals(privateKey.keyType(), publicKey.keyType())) {
      throw new IllegalArgumentException(
          "privateKey and publicKey do not have the same key type.");
    }

    if (privateKey.class_() == null) {
      privateKey.class_(PKCS11T.CKO_PRIVATE_KEY);
    } else if (privateKey.class_() != PKCS11T.CKO_PRIVATE_KEY) {
      throw new IllegalArgumentException(
          "privateKey must have the class CKO_PRIVATE_KEY");
    }

    if (publicKey.class_() == null) {
      publicKey.class_(PKCS11T.CKO_PUBLIC_KEY);
    } else if (publicKey.class_() != PKCS11T.CKO_PUBLIC_KEY) {
      throw new IllegalArgumentException(
          "publicKey must have the class CKO_PUBLIC_KEY");
    }
  }

  public Template privateKey() {
    return privateKey;
  }

  public Template publicKey() {
    return publicKey;
  }

  public KeyPairTemplate derive(Boolean derive) {
    privateKey.derive(derive);
    return this;
  }

  public KeyPairTemplate decryptEncrypt(Boolean decryptEncrypt) {
    privateKey.decrypt(decryptEncrypt);
    publicKey.encrypt(decryptEncrypt);
    return this;
  }

  public KeyPairTemplate ecParams(byte[] ecParams) {
    privateKey.ecParams(ecParams);
    publicKey.ecParams(ecParams);
    return this;
  }

  public KeyPairTemplate endDate(Instant endDate) {
    privateKey.endDate(endDate);
    publicKey.endDate(endDate);
    return this;
  }

  public byte[] id() throws PKCS11Exception {
    byte[] privId = privateKey.id();
    byte[] pubId = publicKey.id();
    if (!Arrays.equals(privId, pubId)) {
      // Private key and public key do not have the same CKA_ID
      throw new PKCS11Exception(PKCS11T.CKR_TEMPLATE_INCONSISTENT);
    }
    return privId;
  }

  public KeyPairTemplate id(byte[] id) {
    privateKey.id(id);
    publicKey.id(id);
    return this;
  }

  public KeyPairTemplate keyType(long keyType) {
    privateKey.keyType(keyType);
    publicKey.keyType(keyType);
    return this;
  }

  public KeyPairTemplate labels(String label) {
    return labels(label, label);
  }

  public KeyPairTemplate labels(String privateKeyLabel, String publicKeyLabel) {
    if (privateKeyLabel != null) {
      privateKey.label(privateKeyLabel);
    }
    if (publicKeyLabel != null) {
      publicKey.label(publicKeyLabel);
    }
    return this;
  }

  public KeyPairTemplate local(Boolean local) {
    privateKey.local(local);
    publicKey.local(local);
    return this;
  }

  public KeyPairTemplate modifiable(Boolean modifiable) {
    privateKey.modifiable(modifiable);
    publicKey.modifiable(modifiable);
    return this;
  }

  public KeyPairTemplate private_(Boolean private_) {
    return private_(private_, private_);
  }

  public KeyPairTemplate private_(Boolean privateKeyPrivate,
                                  Boolean publicKeyPrivate) {
    if (privateKeyPrivate != null) {
      privateKey.private_(privateKeyPrivate);
    }

    if (publicKeyPrivate != null) {
      publicKey.private_(publicKeyPrivate);
    }
    return this;
  }

  public KeyPairTemplate signVerify(Boolean signVerify) {
    privateKey.sign(signVerify);
    publicKey.verify(signVerify);
    return this;
  }

  public KeyPairTemplate signVerifyRecover(Boolean signVerifyRecover) {
    privateKey.signRecover(signVerifyRecover);
    publicKey.verifyRecover(signVerifyRecover);
    return this;
  }

  public KeyPairTemplate startDate(Instant startDate) {
    privateKey.startDate(startDate);
    publicKey.startDate(startDate);
    return this;
  }

  public KeyPairTemplate subject(byte[] subject) {
    privateKey.subject(subject);
    publicKey.subject(subject);
    return this;
  }

  public KeyPairTemplate token(Boolean token) {
    privateKey.token(token);
    publicKey.token(token);
    return this;
  }

  public KeyPairTemplate unwrapWrap(Boolean unwrapWrap) {
    privateKey.unwrap(unwrapWrap);
    publicKey.wrap(unwrapWrap);
    return this;
  }

  @Override
  public String toString() {
    return "Private Key Template:\n" + privateKey.toString(false, "  ")
        + "\nPublic Key Template:\n" + publicKey.toString(false, "  ");
  }

}
