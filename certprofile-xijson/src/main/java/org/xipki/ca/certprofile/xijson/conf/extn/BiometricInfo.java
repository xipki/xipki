// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.type.TripleState;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Extension BiometricInfo.
 *
 * @author Lijun Liao (xipki)
 */

public class BiometricInfo implements JsonEncodable {

  public enum BiometricType {

    picture,
    handwrittenSignature

  } // class BiometricTypeType

  private final List<BiometricType> types;

  private final List<HashAlgo> hashAlgorithms;

  private final TripleState includeSourceDataUri;

  public BiometricInfo(List<BiometricType> types,
                       List<HashAlgo> hashAlgorithms,
                       TripleState includeSourceDataUri) {
    this.types = Args.notEmpty(types, "types");
    this.hashAlgorithms = Args.notEmpty(hashAlgorithms, "hashAlgorithms");
    this.includeSourceDataUri = Args.notNull(includeSourceDataUri,
        "includeSourceDataUri");
  }

  public TripleState getIncludeSourceDataUri() {
    return includeSourceDataUri;
  }

  public boolean allowsHashAlgo(HashAlgo hashAlgo) {
    return hashAlgorithms != null && hashAlgorithms.contains(hashAlgo);
  }

  public boolean allowsType(int type) {
    for (BiometricType t : types) {
      if (t == BiometricType.picture) {
        if (type == 0) {
          return true;
        }
      } else if (t == BiometricType.handwrittenSignature) {
        if (type == 1) {
          return true;
        }
      }
    }

    return false;
  }

  @Override
  public JsonMap toCodec() {
    List<String> hashAlgorithmsList = new ArrayList<>(hashAlgorithms.size());
    for (HashAlgo hashAlgo : hashAlgorithms) {
      hashAlgorithmsList.add(hashAlgo.getJceName());
    }

    return new JsonMap().putEnums("types", types)
        .putStrings("hashAlgorithms", hashAlgorithmsList)
        .putEnum("includeSourceDataUri", includeSourceDataUri);
  }

  public static BiometricInfo parse(JsonMap json) throws CodecException {
    List<String> list = json.getStringList("hashAlgorithms");
    List<HashAlgo> hashAlgorithms = new ArrayList<>(list.size());
    for (String v : list) {
      try {
        hashAlgorithms.add(HashAlgo.getInstance(v));
      } catch (NoSuchAlgorithmException e) {
        throw new CodecException(e);
      }
    }

    return new BiometricInfo(
        json.getEnumList("types", BiometricType.class), hashAlgorithms,
        json.getNnEnum("includeSourceDataUri", TripleState.class));
  }

} // class BiometricInfo
