// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.security.NoSuchAlgorithmException;

/**
 * @author Lijun Liao (xipki)
 */
public class SecurityCodecMap extends JsonMap {

  public SecurityCodecMap put(String key, KeyUsage value) {
    putEnum(key, value);
    return this;
  }

  public KeyUsage getNnKeyUsage(String key) throws CodecException {
    return nonNull(key, getKeyUsage(key));
  }

  public KeyUsage getKeyUsage(String key) throws CodecException {
    String str = getString(key);
    return (str == null) ? null : KeyUsage.getKeyUsage(str);
  }

  public SecurityCodecMap put(String key, KeySpec value) {
    putEnum(key, value);
    return this;
  }

  public KeySpec getNnKeySpec(String key) throws CodecException {
    return nonNull(key, getKeySpec(key));
  }

  public KeySpec getKeySpec(String key) throws CodecException {
    String str = getString(key);
    try {
      return (str == null) ? null : KeySpec.ofKeySpec(str);
    } catch (NoSuchAlgorithmException e) {
      throw new CodecException(e);
    }
  }

  public SecurityCodecMap put(String key, SignSpec value) {
    putEnum(key, value);
    return this;
  }

  public SignSpec getNnSignSpec(String key) throws CodecException {
    return nonNull(key, getSignSpec(key));
  }

  public SignSpec getSignSpec(String key) throws CodecException {
    String str = getString(key);
    try {
      return (str == null) ? null : SignSpec.ofSignSpec(str);
    } catch (NoSuchAlgorithmException e) {
      throw new CodecException(e);
    }
  }

}
