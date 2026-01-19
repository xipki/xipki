// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.PKCS11T;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * Objects of this class represent the attribute types.
 *
 * @author Lijun Liao (xipki)
 */
public class AttributeTypes {

  private final Set<Long> types = new HashSet<>();

  public AttributeTypes() {
  }

  public AttributeTypes(long... types) {
    if (types != null) {
      for (long type : types) {
        this.types.add(type);
      }
    }
  }

  public boolean contains(long type) {
    return types.contains(type);
  }

  public int size() {
    return types.size();
  }

  public boolean remove(long type) {
    return types.remove(type);
  }

  public Set<Long> getTypes() {
    return Collections.unmodifiableSet(types);
  }

  public AttributeTypes attr(long attrType) {
    this.types.add(attrType);
    return this;
  }

  @Override
  public int hashCode() {
    return types.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    return obj instanceof AttributeTypes &&
        this.types.equals(((AttributeTypes) obj).types);
  }

  @Override
  public String toString() {
    return toString("");
  }

  public String toString(String indent) {
    StringBuilder sb = new StringBuilder(200);
    sb.append(indent).append("Attribute Types:\n");
    String indent2 = indent + "  ";

    // sort the attributes to print
    List<Long> copy = new ArrayList<>(this.types);
    Collections.sort(copy);

    for (long type : copy) {
      sb.append(indent2).append(PKCS11T.ckaCodeToName(type))
          .append("\n");
    }

    return sb.toString();
  }

  public AttributeTypes allowedMechanisms() {
    return attr(CKA_ALLOWED_MECHANISMS);
  }

  public AttributeTypes alwaysAuthenticate() {
    return attr(CKA_ALWAYS_AUTHENTICATE);
  }

  public AttributeTypes alwaysSensitive() {
    return attr(CKA_ALWAYS_SENSITIVE);
  }

  public AttributeTypes application() {
    return attr(CKA_APPLICATION);
  }

  public AttributeTypes base() {
    return attr(CKA_BASE);
  }

  public AttributeTypes certificateCategory() {
    return attr(CKA_CERTIFICATE_CATEGORY);
  }

  public AttributeTypes certificateType() {
    return attr(CKA_CERTIFICATE_TYPE);
  }

  public AttributeTypes class_() {
    return attr(CKA_CLASS);
  }

  public AttributeTypes coefficient() {
    return attr(CKA_COEFFICIENT);
  }

  public AttributeTypes copyable() {
    return attr(CKA_COPYABLE);
  }

  public AttributeTypes decrypt() {
    return attr(CKA_DECRYPT);
  }

  public AttributeTypes derive() {
    return attr(CKA_DERIVE);
  }

  public AttributeTypes deriveTemplate() {
    return attr(CKA_DERIVE_TEMPLATE);
  }

  public AttributeTypes destroyable() {
    return attr(CKA_DESTROYABLE);
  }

  public AttributeTypes ecParams() {
    return attr(CKA_EC_PARAMS);
  }

  public AttributeTypes ecPoint() {
    return attr(CKA_EC_POINT);
  }

  public AttributeTypes encrypt() {
    return attr(CKA_ENCRYPT);
  }

  public AttributeTypes endDate() {
    return attr(CKA_END_DATE);
  }

  public AttributeTypes exponent1() {
    return attr(CKA_EXPONENT_1);
  }

  public AttributeTypes exponent2() {
    return attr(CKA_EXPONENT_2);
  }

  public AttributeTypes extractable() {
    return attr(CKA_EXTRACTABLE);
  }

  public AttributeTypes hashOfIssuerPublicKey() {
    return attr(CKA_HASH_OF_ISSUER_PUBLIC_KEY);
  }

  public AttributeTypes hashOfSubjectPublicKey() {
    return attr(CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
  }

  public AttributeTypes id() {
    return attr(CKA_ID);
  }

  public AttributeTypes issuer() {
    return attr(CKA_ISSUER);
  }

  public AttributeTypes keyGenMechanism() {
    return attr(CKA_KEY_GEN_MECHANISM);
  }

  public AttributeTypes keyType() {
    return attr(CKA_KEY_TYPE);
  }

  public AttributeTypes label() {
    return attr(CKA_LABEL);
  }

  public AttributeTypes local() {
    return attr(CKA_LOCAL);
  }

  public AttributeTypes modifiable() {
    return attr(CKA_MODIFIABLE);
  }

  public AttributeTypes modulus() {
    return attr(CKA_MODULUS);
  }

  public AttributeTypes modulusBits() {
    return attr(CKA_MODULUS_BITS);
  }

  public AttributeTypes neverExtractable() {
    return attr(CKA_NEVER_EXTRACTABLE);
  }

  public AttributeTypes prime() {
    return attr(CKA_PRIME);
  }

  public AttributeTypes prime1() {
    return attr(CKA_PRIME_1);
  }

  public AttributeTypes prime2() {
    return attr(CKA_PRIME_2);
  }

  public AttributeTypes primeBits() {
    return attr(CKA_PRIME_BITS);
  }

  public AttributeTypes private_() {
    return attr(CKA_PRIVATE);
  }

  public AttributeTypes privateExponent() {
    return attr(CKA_PRIVATE_EXPONENT);
  }

  public AttributeTypes publicExponent() {
    return attr(CKA_PUBLIC_EXPONENT);
  }

  public AttributeTypes publicKeyInfo() {
    return attr(CKA_PUBLIC_KEY_INFO);
  }

  public AttributeTypes sensitive() {
    return attr(CKA_SENSITIVE);
  }

  public AttributeTypes serialNumber() {
    return attr(CKA_SERIAL_NUMBER);
  }

  public AttributeTypes sign() {
    return attr(CKA_SIGN);
  }

  public AttributeTypes signRecover() {
    return attr(CKA_SIGN_RECOVER);
  }

  public AttributeTypes startDate() {
    return attr(CKA_START_DATE);
  }

  public AttributeTypes subject() {
    return attr(CKA_SUBJECT);
  }

  public AttributeTypes subprime() {
    return attr(CKA_SUBPRIME);
  }

  public AttributeTypes token() {
    return attr(CKA_TOKEN);
  }

  public AttributeTypes trusted() {
    return attr(CKA_TRUSTED);
  }

  public AttributeTypes uniqueId() {
    return attr(CKA_UNIQUE_ID);
  }

  public AttributeTypes unwrap() {
    return attr(CKA_UNWRAP);
  }

  public AttributeTypes unwrapTemplate() {
    return attr(CKA_UNWRAP_TEMPLATE);
  }

  public AttributeTypes url() {
    return attr(CKA_URL);
  }

  public AttributeTypes value() {
    return attr(CKA_VALUE);
  }

  public AttributeTypes valueLen() {
    return attr(CKA_VALUE_LEN);
  }

  public AttributeTypes verify() {
    return attr(CKA_VERIFY);
  }

  public AttributeTypes verifyRecover() {
    return attr(CKA_VERIFY_RECOVER);
  }

  public AttributeTypes wrap() {
    return attr(CKA_WRAP);
  }

  public AttributeTypes wrapTemplate() {
    return attr(CKA_WRAP_TEMPLATE);
  }

  public AttributeTypes wrapWithTrusted() {
    return attr(CKA_WRAP_WITH_TRUSTED);
  }

  /* new post-quantum (general) */
  public AttributeTypes parameterSet() {
    return attr(CKA_PARAMETER_SET);
  }

  /* KEM */
  public AttributeTypes encapsulateTemplate() {
    return attr(CKA_ENCAPSULATE_TEMPLATE);
  }

  public AttributeTypes decapsulateTemplate() {
    return attr(CKA_DECAPSULATE_TEMPLATE);
  }

  public AttributeTypes encapsulate() {
    return attr(CKA_ENCAPSULATE);
  }

  public AttributeTypes decapsulate() {
    return attr(CKA_DECAPSULATE);
  }

  /* new post-quantum (general) */
  public AttributeTypes seed() {
    return attr(CKA_SEED);
  }

}
