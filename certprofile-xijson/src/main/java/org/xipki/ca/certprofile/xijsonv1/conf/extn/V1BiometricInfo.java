// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.certprofile.xijson.conf.extn.BiometricInfo;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableInt;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.security.HashAlgo;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
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

public class V1BiometricInfo {

  private static final Logger LOG =
      LoggerFactory.getLogger(V1BiometricInfo.class);

  private final List<BiometricType> types;

  private final List<DescribableOid> hashAlgorithms;

  private final TripleState includeSourceDataUri;

  private V1BiometricInfo(List<BiometricType> types,
                         List<DescribableOid> hashAlgorithms,
                         TripleState includeSourceDataUri) {
    this.types = Args.notEmpty(types, "types");
    this.hashAlgorithms = Args.notEmpty(hashAlgorithms, "hashAlgorithms");
    this.includeSourceDataUri = Args.notNull(includeSourceDataUri,
        "includeSourceDataUri");
  }

  public static V1BiometricInfo parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("types");
    List<BiometricType> types = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      types.add(BiometricType.parse(v));
    }

    List<DescribableOid> hashAlgorithms = DescribableOid.parseList(
        json.getNnList("hashAlgorithms"));

    TripleState includeSourceDataUri = json.getNnEnum("includeSourceDataUri",
        TripleState.class);
    return new V1BiometricInfo(types, hashAlgorithms, includeSourceDataUri);
  }

  public BiometricInfo toV2() {

    List<HashAlgo> v2HashAlgorithms = new ArrayList<>(hashAlgorithms.size());
    for (DescribableOid oid : hashAlgorithms) {
      HashAlgo ha;
      try {
        ha = HashAlgo.getInstance(oid.oid());
      } catch (NoSuchAlgorithmException e) {
        LOG.warn("ignore unknown hash algorithm '{}'", oid.getOid());
        continue;
      }
      v2HashAlgorithms.add(ha);
    }

    List<BiometricInfo.BiometricType> v2Types = new ArrayList<>(types.size());
    for (BiometricType v1Type : types) {
      if (v1Type.getPredefined() != null) {
        int value = v1Type.getPredefined().getValue();
        if (value == 0) {
          v2Types.add(BiometricInfo.BiometricType.picture);
        } else if (value == 1) {
          v2Types.add(BiometricInfo.BiometricType.handwrittenSignature);
        }
      }
    }

    return new BiometricInfo(v2Types, v2HashAlgorithms, includeSourceDataUri);
  }

  private static class BiometricType {

    private final DescribableInt predefined;

    private final DescribableOid oid;

    private BiometricType(DescribableInt predefined) {
      this.predefined = Args.notNull(predefined, "predefined");
      this.oid = null;
    }

    private BiometricType(DescribableOid oid) {
      this.predefined = null;
      this.oid = Args.notNull(oid, "oid");
    }

    public DescribableInt getPredefined() {
      return predefined;
    }

    public DescribableOid getOid() {
      return oid;
    }

    public static BiometricType parse(JsonMap json) throws CodecException {
      DescribableInt predefined = DescribableInt.parse(json, "predefined");
      DescribableOid oid = DescribableOid.parse(json, "oid");

      Args.exactOne(predefined, "predefined", oid, "oid");
      return (predefined != null) ? new BiometricType(predefined)
          : new BiometricType(oid);
    }

  } // class BiometricTypeType

}
