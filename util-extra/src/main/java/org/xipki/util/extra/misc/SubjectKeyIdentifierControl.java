// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.extra.misc;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Extension SubjectKeyIdentifierControl.
 *
 * @author Lijun Liao (xipki)
 */
public class SubjectKeyIdentifierControl implements JsonEncodable {

  private final SubjectKeyIdentifierMethod method;

  private final String hashAlgo;

  private final TruncateMethod truncateMethod;

  private final Integer truncateByteSize;

  public SubjectKeyIdentifierControl() {
    this(null, null, null, null);
  }

  public SubjectKeyIdentifierControl(
      SubjectKeyIdentifierMethod method, String hashAlgo,
      TruncateMethod truncateMethod, Integer truncateByteSize) {
    this.method = method;
    this.hashAlgo = hashAlgo;
    this.truncateMethod = truncateMethod;
    this.truncateByteSize = truncateByteSize;
  }

  public SubjectKeyIdentifierMethod getMethod() {
    return method;
  }

  public String hashAlgo() {
    return hashAlgo;
  }

  public TruncateMethod truncateMethod() {
    return truncateMethod;
  }

  public Integer truncateByteSize() {
    return truncateByteSize;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEnum("method", method)
        .put("hashAlgo", hashAlgo)
        .putEnum("truncateMethod", truncateMethod)
        .put("truncateByteSize", truncateByteSize);
  }

  public static SubjectKeyIdentifierControl parse(JsonMap json)
      throws CodecException {
    return new SubjectKeyIdentifierControl(
        json.getEnum("method", SubjectKeyIdentifierMethod.class),
        json.getString("hashAlgo"),
        json.getEnum("truncateMethod", TruncateMethod.class),
        json.getInt("truncateByteSize"));
  }

  public byte[] computeKeyIdentifier(byte[] keyData) {
    SubjectKeyIdentifierMethod method = this.method;
    if (method == null) {
      method = SubjectKeyIdentifierMethod.METHOD1;
    }

    String hashAlgo = this.hashAlgo;
    if (hashAlgo == null) {
      hashAlgo = "SHA1";
    }

    TruncateMethod truncateMethod = this.truncateMethod;
    if (truncateByteSize != null) {
      if (truncateMethod == null) {
        truncateMethod = TruncateMethod.LEFT;
      }
    }

    MessageDigest md;
    try {
      md = MessageDigest.getInstance(hashAlgo);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    byte[] hashValue = md.digest(keyData);

    if (method == SubjectKeyIdentifierMethod.METHOD2) {
      byte[] id = Arrays.copyOfRange(hashValue, 8, 16);
      id[0] = (byte) ((0x0F & id[0]) | 0x40);
      return id;
    } else { // use METHOD_1
      int hLen = hashValue.length;
      if (truncateByteSize == null || (truncateByteSize >= hLen)) {
        return hashValue;
      }

      if (truncateMethod == TruncateMethod.LEFT) {
        return Arrays.copyOfRange(hashValue, 0, truncateByteSize);
      } else {
        return Arrays.copyOfRange(hashValue, hLen - truncateByteSize, hLen);
      }
    }
  }

  public enum SubjectKeyIdentifierMethod {
    METHOD1,
    METHOD2
  }

  public enum TruncateMethod {
    LEFT,
    RIGHT
  }

}
