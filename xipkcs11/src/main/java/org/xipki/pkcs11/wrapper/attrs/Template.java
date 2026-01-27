// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.jni.JniUtil;
import org.xipki.pkcs11.wrapper.type.CkDate;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.asn1.Asn1Util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * Object of this class represents the attribute vector.
 *
 * @author Lijun Liao (xipki)
 */
public class Template {

  private final List<Attribute> attributes = new LinkedList<>();

  public Template() {
  }

  public Template(Attribute... attributes) {
    if (attributes != null) {
      for (Attribute attr : attributes) {
        if (attr != null) {
          attr(attr);
        }
      }
    }
  }

  public Template(Collection<Attribute> attributes) {
    if (attributes != null) {
      for (Attribute attr : attributes) {
        if (attr != null) {
          attr(attr);
        }
      }
    }
  }

  public static Template newSecretKey() {
    return new Template().class_(CKO_SECRET_KEY);
  }

  public static Template newSecretKey(long keyType) {
    return newSecretKey().keyType(keyType);
  }

  public static Template newPrivateKey() {
    return new Template().class_(CKO_PRIVATE_KEY);
  }

  public static Template newPrivateKey(long keyType) {
    return newPrivateKey().keyType(keyType);
  }

  public static Template newPublicKey() {
    return new Template().class_(CKO_PUBLIC_KEY);
  }

  public static Template newPublicKey(long keyType) {
    return newPublicKey().keyType(keyType);
  }

  public int getSize() {
    return attributes.size();
  }

  public boolean hasAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.type() == type) {
        return true;
      }
    }
    return false;
  }

  public long[] getTypes() {
    long[] ret = new long[attributes.size()];
    int idx = 0;
    for (Attribute attr : attributes) {
      ret[idx++] = attr.type;
    }
    return ret;
  }

  public Template attr(long attrType, Object attrValue) {
    if (attrValue != null) {
      return attr(Attribute.getInstance(attrType, attrValue));
    }
    return this;
  }

  public Attribute remove(long type) {
    if (!attributes.isEmpty()) {
      int oldAttrIdx = -1;
      for (int i = 0; i < attributes.size(); i++) {
        if (attributes.get(i).type() == type) {
          oldAttrIdx = i;
          break;
        }
      }

      if (oldAttrIdx != -1) {
        return attributes.remove(oldAttrIdx);
      }
    }

    return null;
  }

  public Template attr(Attribute attr) {
    remove(attr.type());
    attributes.add(attr);
    return this;
  }

  public List<Attribute> snapshot() {
    return Collections.unmodifiableList(attributes);
  }

  public Attribute getAttribute(long type) {
    for (Attribute attr : attributes) {
      if (attr.type() == type) {
        return attr;
      }
    }
    return null;
  }

  public Boolean getBooleanAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Long getLongAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Integer getIntAttrValue(long type) {
    Long value = getLongAttrValue(type);
    return value == null ? null : value.intValue();
  }

  public String getStringAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((StringAttribute) attr).getValue();
  }

  public byte[] getByteArrayAttrValue(long type) {
    Attribute attr = getAttribute(type);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  @Override
  public String toString() {
    return toString(true, "");
  }

  public String toString(boolean withName, String indent) {
    StringBuilder sb = new StringBuilder(200);
    String indent2 = indent;
    if (withName) {
      sb.append(indent).append("Attributes:");
      indent2 += "  ";
    }

    // sort the attributes to print
    List<Attribute> copy = new ArrayList<>(attributes);
    copy.sort(Comparator.comparingLong(Attribute::type));

    int nameLen = 0;
    for (Attribute attribute : copy) {
      if (!attribute.isNullValue()) {
        nameLen = Math.max(nameLen, ckaCodeToName(attribute.type()).length());
      }
    }

    nameLen = Math.min(nameLen, 30);

    for (Attribute attribute : copy) {
      if (attribute.isNullValue()) {
        continue;
      }

      if (sb.length() > 0) {
        sb.append("\n");
      }

      sb.append(attribute.toString(true, nameLen, indent2));
    }

    return sb.toString();
  }

  public long[] allowedMechanisms() {
    Attribute attr = getAttribute(CKA_ALLOWED_MECHANISMS);
    return attr == null ? null : ((LongArrayAttribute) attr).getValue();
  }

  public Template allowedMechanisms(long[] allowedMechanisms) {
    return attr(CKA_ALLOWED_MECHANISMS, allowedMechanisms);
  }

  public Boolean alwaysAuthenticate() {
    Attribute attr = getAttribute(CKA_ALWAYS_AUTHENTICATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template alwaysAuthenticate(Boolean alwaysAuthenticate) {
    return attr(CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate);
  }

  public Boolean alwaysSensitive() {
    Attribute attr = getAttribute(CKA_ALWAYS_SENSITIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template alwaysSensitive(Boolean alwaysSensitive) {
    return attr(CKA_ALWAYS_SENSITIVE, alwaysSensitive);
  }

  public BigInteger base() {
    Attribute attr = getAttribute(CKA_BASE);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template base(BigInteger base) {
    return attr(CKA_BASE, base);
  }

  public Long class_() {
    Attribute attr = getAttribute(CKA_CLASS);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Template class_(Long class_) {
    return attr(CKA_CLASS, class_);
  }

  public BigInteger coefficient() {
    Attribute attr = getAttribute(CKA_COEFFICIENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template coefficient(BigInteger coefficient) {
    return attr(CKA_COEFFICIENT, coefficient);
  }

  public Template copyable(Boolean copyable) {
    return attr(CKA_COPYABLE, copyable);
  }

  public Boolean decrypt() {
    Attribute attr = getAttribute(CKA_DECRYPT);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template decrypt(Boolean decrypt) {
    return attr(CKA_DECRYPT, decrypt);
  }

  public Boolean derive() {
    Attribute attr = getAttribute(CKA_DERIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template derive(Boolean derive) {
    return attr(CKA_DERIVE, derive);
  }

  public Template deriveTemplate() {
    Attribute attr = getAttribute(CKA_DERIVE_TEMPLATE);
    return attr == null ? null : ((TemplateAttribute) attr).getValue();
  }

  public Template deriveTemplate(Template deriveTemplate) {
    return attr(CKA_DERIVE_TEMPLATE, deriveTemplate);
  }

  public Boolean destroyable() {
    Attribute attr = getAttribute(CKA_DESTROYABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template destroyable(Boolean destroyable) {
    return attr(CKA_DESTROYABLE, destroyable);
  }

  public byte[] ecParams() {
    Attribute attr = getAttribute(CKA_EC_PARAMS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template ecParams(byte[] ecParams) {
    return attr(CKA_EC_PARAMS, ecParams);
  }

  public byte[] derEcPoint() {
    Attribute attr = getAttribute(CKA_EC_POINT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template derEcPoint(byte[] derEcPoint) {
    return attr(CKA_EC_POINT, derEcPoint);
  }

  public byte[] ecPoint() {
    byte[] derEcPoint = derEcPoint();
    if (derEcPoint == null) {
      return null;
    }

    try {
      return Asn1Util.readOctetsFromASN1OctetString(derEcPoint);
    } catch (CodecException e) {
      return derEcPoint;
    }
  }

  public Template ecPoint(byte[] ecPoint) {
    return derEcPoint(Asn1Util.toOctetString(ecPoint));
  }

  public Boolean encrypt() {
    Attribute attr = getAttribute(CKA_ENCRYPT);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template encrypt(Boolean encrypt) {
    return attr(CKA_ENCRYPT, encrypt);
  }

  public Instant endDate() {
    Attribute attr = getAttribute(CKA_END_DATE);
    return attr == null ? null : ((DateAttribute) attr).getValue();
  }

  public Template endDate(Instant endDate) {
    return attr(CKA_END_DATE, endDate);
  }

  public BigInteger exponent1() {
    Attribute attr = getAttribute(CKA_EXPONENT_1);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template exponent1(BigInteger exponent1) {
    return attr(CKA_EXPONENT_1, exponent1);
  }

  public BigInteger exponent2() {
    Attribute attr = getAttribute(CKA_EXPONENT_2);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template exponent2(BigInteger exponent2) {
    return attr(CKA_EXPONENT_2, exponent2);
  }

  public Boolean extractable() {
    Attribute attr = getAttribute(CKA_EXTRACTABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template extractable(Boolean extractable) {
    return attr(CKA_EXTRACTABLE, extractable);
  }

  public byte[] id() {
    Attribute attr = getAttribute(CKA_ID);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template id(byte[] id) {
    return attr(CKA_ID, id);
  }

  public byte[] issuer() {
    Attribute attr = getAttribute(CKA_ISSUER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template issuer(byte[] issuer) {
    return attr(CKA_ISSUER, issuer);
  }

  public Long keyGenMechanism() {
    Attribute attr = getAttribute(CKA_KEY_GEN_MECHANISM);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Template keyGenMechanism(Long keyGenMechanism) {
    return attr(CKA_KEY_GEN_MECHANISM, keyGenMechanism);
  }

  public Long keyType() {
    Attribute attr = getAttribute(CKA_KEY_TYPE);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  public Template keyType(Long keyType) {
    return attr(CKA_KEY_TYPE, keyType);
  }

  public String label() {
    Attribute attr = getAttribute(CKA_LABEL);
    return attr == null ? null : ((StringAttribute) attr).getValue();
  }

  public Template label(String label) {
    return attr(CKA_LABEL, label);
  }

  public Boolean local() {
    Attribute attr = getAttribute(CKA_LOCAL);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template local(Boolean local) {
    return attr(CKA_LOCAL, local);
  }

  public Boolean modifiable() {
    Attribute attr = getAttribute(CKA_MODIFIABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template modifiable(Boolean modifiable) {
    return attr(CKA_MODIFIABLE, modifiable);
  }

  public BigInteger modulus() {
    Attribute attr = getAttribute(CKA_MODULUS);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template modulus(BigInteger modulus) {
    return attr(CKA_MODULUS, modulus);
  }

  public Integer modulusBits() {
    Attribute attr = getAttribute(CKA_MODULUS_BITS);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public Template modulusBits(Integer modulusBits) {
    return attr(CKA_MODULUS_BITS, modulusBits);
  }

  public Boolean neverExtractable() {
    Attribute attr = getAttribute(CKA_NEVER_EXTRACTABLE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template neverExtractable(Boolean neverExtractable) {
    return attr(CKA_NEVER_EXTRACTABLE, neverExtractable);
  }

  public BigInteger prime() {
    Attribute attr = getAttribute(CKA_PRIME);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template prime(BigInteger prime) {
    return attr(CKA_PRIME, prime);
  }

  public BigInteger prime1() {
    Attribute attr = getAttribute(CKA_PRIME_1);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template prime1(BigInteger prime1) {
    return attr(CKA_PRIME_1, prime1);
  }

  public BigInteger prime2() {
    Attribute attr = getAttribute(CKA_PRIME_2);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template prime2(BigInteger prime2) {
    return attr(CKA_PRIME_2, prime2);
  }

  public Boolean private_() {
    Attribute attr = getAttribute(CKA_PRIVATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template private_(Boolean private_) {
    return attr(CKA_PRIVATE, private_);
  }

  public BigInteger privateExponent() {
    Attribute attr = getAttribute(CKA_PRIVATE_EXPONENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template privateExponent(BigInteger privateExponent) {
    return attr(CKA_PRIVATE_EXPONENT, privateExponent);
  }

  public BigInteger publicExponent() {
    Attribute attr = getAttribute(CKA_PUBLIC_EXPONENT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template publicExponent(BigInteger publicExponent) {
    return attr(CKA_PUBLIC_EXPONENT, publicExponent);
  }

  public Boolean sensitive() {
    Attribute attr = getAttribute(CKA_SENSITIVE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template sensitive(Boolean sensitive) {
    return attr(CKA_SENSITIVE, sensitive);
  }

  public byte[] serialNumber() {
    Attribute attr = getAttribute(CKA_SERIAL_NUMBER);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template serialNumber(byte[] serialNumber) {
    return attr(CKA_SERIAL_NUMBER, serialNumber);
  }

  public Boolean sign() {
    Attribute attr = getAttribute(CKA_SIGN);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template sign(Boolean sign) {
    return attr(CKA_SIGN, sign);
  }

  public Boolean signRecover() {
    Attribute attr = getAttribute(CKA_SIGN_RECOVER);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template signRecover(Boolean signRecover) {
    return attr(CKA_SIGN_RECOVER, signRecover);
  }

  public Instant startDate() {
    Attribute attr = getAttribute(CKA_START_DATE);
    return attr == null ? null : ((DateAttribute) attr).getValue();
  }

  public Template startDate(Instant startDate) {
    return attr(CKA_START_DATE, startDate);
  }

  public byte[] subject() {
    Attribute attr = getAttribute(CKA_SUBJECT);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template subject(byte[] subject) {
    return attr(CKA_SUBJECT, subject);
  }

  public BigInteger subprime() {
    Attribute attr = getAttribute(CKA_SUBPRIME);
    return attr == null ? null : ((ByteArrayAttribute) attr).getBigIntValue();
  }

  public Template subprime(BigInteger subprime) {
    return attr(CKA_SUBPRIME, subprime);
  }

  public Boolean token() {
    Attribute attr = getAttribute(CKA_TOKEN);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template token(Boolean token) {
    return attr(CKA_TOKEN, token);
  }

  public Boolean trusted() {
    Attribute attr = getAttribute(CKA_TRUSTED);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template trusted(Boolean trusted) {
    return attr(CKA_TRUSTED, trusted);
  }

  public String uniqueId() {
    Attribute attr = getAttribute(CKA_UNIQUE_ID);
    return attr == null ? null : ((StringAttribute) attr).getValue();
  }

  public Template uniqueId(String uniqueId) {
    return attr(CKA_UNIQUE_ID, uniqueId);
  }

  public Boolean unwrap() {
    Attribute attr = getAttribute(CKA_UNWRAP);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template unwrap(Boolean unwrap) {
    return attr(CKA_UNWRAP, unwrap);
  }

  public Template unwrapTemplate() {
    Attribute attr = getAttribute(CKA_UNWRAP_TEMPLATE);
    return attr == null ? null : ((TemplateAttribute) attr).getValue();
  }

  public Template unwrapTemplate(Template unwrapTemplate) {
    return attr(CKA_UNWRAP_TEMPLATE, unwrapTemplate);
  }

  public String url() {
    Attribute attr = getAttribute(CKA_URL);
    return attr == null ? null : ((StringAttribute) attr).getValue();
  }

  public Template url(String url) {
    return attr(CKA_URL, url);
  }

  public byte[] value() {
    Attribute attr = getAttribute(CKA_VALUE);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public Template value(byte[] value) {
    return attr(CKA_VALUE, value);
  }

  public Integer valueLen() {
    Attribute attr = getAttribute(CKA_VALUE_LEN);
    return attr == null ? null : ((LongAttribute) attr).getIntValue();
  }

  public Template valueLen(Integer valueLen) {
    return attr(CKA_VALUE_LEN, valueLen);
  }

  public Boolean verify() {
    Attribute attr = getAttribute(CKA_VERIFY);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template verify(Boolean verify) {
    return attr(CKA_VERIFY, verify);
  }

  public Boolean verifyRecover() {
    Attribute attr = getAttribute(CKA_VERIFY_RECOVER);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template verifyRecover(Boolean verifyRecover) {
    return attr(CKA_VERIFY_RECOVER, verifyRecover);
  }

  public Boolean wrap() {
    Attribute attr = getAttribute(CKA_WRAP);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template wrap(Boolean wrap) {
    return attr(CKA_WRAP, wrap);
  }

  public Template wrapTemplate() {
    Attribute attr = getAttribute(CKA_WRAP_TEMPLATE);
    return attr == null ? null : ((TemplateAttribute) attr).getValue();
  }

  public Template wrapTemplate(Template wrapTemplate) {
    return attr(CKA_WRAP_TEMPLATE, wrapTemplate);
  }

  public Boolean wrapWithTrusted() {
    Attribute attr = getAttribute(CKA_WRAP_WITH_TRUSTED);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template wrapWithTrusted(Boolean wrapWithTrusted) {
    return attr(CKA_WRAP_WITH_TRUSTED, wrapWithTrusted);
  }

  /* new post-quantum (general) */
  public Template parameterSet(long paramSet) {
    return attr(CKA_PARAMETER_SET, paramSet);
  }

  public Long parameterSet() {
    Attribute attr = getAttribute(CKA_PARAMETER_SET);
    return attr == null ? null : ((LongAttribute) attr).getValue();
  }

  /* KEM */
  public Template encapsulateTemplate(Template template) {
    return attr(CKA_ENCAPSULATE_TEMPLATE, template);
  }

  public Template encapsulateTemplate() {
    Attribute attr = getAttribute(CKA_ENCAPSULATE_TEMPLATE);
    return attr == null ? null : ((TemplateAttribute) attr).getValue();
  }

  public Template decapsulateTemplate(Template template) {
    return attr(CKA_DECAPSULATE_TEMPLATE, template);
  }

  public Template decapsulateTemplate() {
    Attribute attr = getAttribute(CKA_DECAPSULATE_TEMPLATE);
    return attr == null ? null : ((TemplateAttribute) attr).getValue();
  }

  public Template encapsulate(Boolean b) {
    return attr(CKA_ENCAPSULATE, b);
  }

  public Boolean encapsulate() {
    Attribute attr = getAttribute(CKA_ENCAPSULATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  public Template decapsulate(Boolean b) {
    return attr(CKA_DECAPSULATE, b);
  }

  public Boolean decapsulate() {
    Attribute attr = getAttribute(CKA_DECAPSULATE);
    return attr == null ? null : ((BooleanAttribute) attr).getValue();
  }

  /* new post-quantum (general) */
  public Template seed(byte[] bytes) {
    return attr(CKA_SEED, bytes);
  }

  public byte[] seed() {
    Attribute attr = getAttribute(CKA_SEED);
    return attr == null ? null : ((ByteArrayAttribute) attr).getValue();
  }

  public List<Attribute> attributes() {
    return attributes;
  }

  public Template attributesAsSensitive(long... ckaTypes) {
    for (Attribute attr : attributes) {
      for (long type : ckaTypes) {
        if (attr.type() == type) {
          attr.sensitive(true);
          break;
        }
      }
    }
    return this;
  }

  public int getEncodedLen(Arch arch) {
    return encodedLen(arch, this);
  }

  public byte[] getEncoded(Arch arch) {
    byte[] dest = new byte[encodedLen(arch, this)];
    encode(arch, this, dest, new AtomicInteger());
    return dest;
  }

  private static int attrValueLen(Arch arch, Attribute attr) {
    final int longSize = arch.longSize();
    if (attr.value() == null) {
      return 0;
    }

    if (attr instanceof BooleanAttribute) {
      return 1;
    } else if (attr instanceof DateAttribute) {
      return 8;
    } else if (attr instanceof VersionAttribute) {
      return 2;
    } else if (attr instanceof LongAttribute) {
      return longSize;
    } else if (attr instanceof ByteArrayAttribute) {
      return ((ByteArrayAttribute) attr).getValue().length;
    } else if (attr instanceof LongArrayAttribute) {
      return ((LongArrayAttribute) attr).getValue().length * longSize;
    } else if (attr instanceof StringAttribute) {
      return ((StringAttribute) attr).getByteArrayValue().length;
    } else if (attr instanceof TemplateAttribute) {
      return encodedLen(arch, ((TemplateAttribute) attr).getValue());
    } else {
      throw new IllegalStateException("shall not reach here.");
    }
  }

  public static int encodedLen(Arch arch, Template template) {
    final int longSize = arch.longSize();
    List<Attribute> attrs = template.attributes();
    int size = longSize; // count
    for (Attribute attr : attrs) {
      size += longSize; // type
      size += longSize; // parameterLen
      size += attrValueLen(arch, attr);
    }
    return size;
  }

  private static void encode(
      Arch arch, Template template, byte[] dest, AtomicInteger off) {
    List<Attribute> attrs = template.attributes();
    final int longSize = attrs.size();
    JniUtil.writeLong(arch, longSize, dest, off);

    for (Attribute attr : attrs) {
      JniUtil.writeLong(arch, attr.type(), dest, off);
      // parameterLen
      int parameterLen = attrValueLen(arch, attr);
      JniUtil.writeLong(arch, parameterLen, dest, off);

      if (attr instanceof BooleanAttribute) {
        boolean v = ((BooleanAttribute) attr).getValue();
        dest[off.getAndIncrement()] = (byte) (v ? 1 : 0);
      } else if (attr instanceof DateAttribute) {
        CkDate v = ((DateAttribute) attr).getCkDateValue();
        String s = v.year() + v.month() + v.day();
        JniUtil.writeFixedLenByteArray(s.getBytes(StandardCharsets.UTF_8),
            dest, off);
      } else if (attr instanceof VersionAttribute) {
        CkVersion v = ((VersionAttribute) attr).getValue();
        dest[off.getAndIncrement()] = v.major();
        dest[off.getAndIncrement()] = v.minor();
      } else if (attr instanceof LongAttribute) {
        long v = ((LongAttribute) attr).getValue();
        JniUtil.writeLong(arch, v, dest, off);
      } else if (attr instanceof ByteArrayAttribute) {
        byte[] v = ((ByteArrayAttribute) attr).getValue();
        JniUtil.writeFixedLenByteArray(v, dest, off);
      } else if (attr instanceof LongArrayAttribute) {
        long[] v = ((LongArrayAttribute) attr).getValue();
        for (long l : v) {
          JniUtil.writeLong(arch, l, dest, off);
        }
      } else if (attr instanceof StringAttribute) {
        byte[] v = ((StringAttribute) attr).getByteArrayValue();
        JniUtil.writeFixedLenByteArray(v, dest, off);
      } else if (attr instanceof TemplateAttribute) {
        Template v = ((TemplateAttribute) attr).getValue();
        encode(arch, v, dest, off);
      } else {
        throw new IllegalStateException("shall not reach here.");
      }
    }
  }

  public static Template decode(Arch arch, byte[] encoded) {
    return decodeTemplate(arch, encoded, new AtomicInteger(0));
  }

  private static Template decodeTemplate(
      Arch arch, byte[] bytes, AtomicInteger off) {
    int count = JniUtil.readInt(arch, bytes, off);
    List<Attribute> attrs = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      long type = JniUtil.readLong(arch, bytes, off);
      Attribute attr = Attribute.getInstance(type);
      attrs.add(attr);

      int parameterLen = JniUtil.readInt(arch, bytes, off);
      if (parameterLen == 0) {
        continue;
      }

      if (attr instanceof BooleanAttribute) {
        boolean v = bytes[off.getAndIncrement()] != 0;
        ((BooleanAttribute) attr).setValue(v);
      } else if (attr instanceof VersionAttribute) {
        CkVersion v = new CkVersion(bytes[off.getAndIncrement()],
            bytes[off.getAndIncrement()]);
        ((VersionAttribute) attr).setValue(v);
      } else if (attr instanceof DateAttribute) {
        byte[] bytesV = Arrays.copyOfRange(bytes, off.get(),
            off.addAndGet(parameterLen));
        CkDate v = new CkDate(new String(bytesV, StandardCharsets.UTF_8));
        ((DateAttribute) attr).setValue(v);
      } else if (attr instanceof LongAttribute) {
        long v = JniUtil.readLong(arch, bytes, off);
        ((LongAttribute) attr).setValue(v);
      } else if (attr instanceof ByteArrayAttribute) {
        byte[] v = Arrays.copyOfRange(bytes, off.get(),
            off.addAndGet(parameterLen));
        ((ByteArrayAttribute) attr).setValue(v);
      } else if (attr instanceof StringAttribute) {
        byte[] v = Arrays.copyOfRange(bytes, off.get(),
            off.addAndGet(parameterLen));
        ((StringAttribute) attr).setValue(v);
      } else if (attr instanceof LongArrayAttribute) {
        int n = parameterLen / arch.longSize();
        long[] value = new long[n];
        for (int j = 0; j < n; j++) {
          value[j] = JniUtil.readLong(arch, bytes, off);
        }
        ((LongArrayAttribute) attr).setValue(value);
      } else if (attr instanceof TemplateAttribute) {
        Template value = decodeTemplate(arch, bytes, off);
        ((TemplateAttribute) attr).setValue(value);
      } else {
        throw new IllegalStateException("shall not reach here");
      }
    }

    return new Template(attrs);
  }

}
