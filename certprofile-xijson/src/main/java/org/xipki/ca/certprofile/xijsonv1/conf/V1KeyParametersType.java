// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.ca.certprofile.xijsonv1.conf.type.V1Range;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * KeyParameters.
 *
 * @author Lijun Liao (xipki)
 */

public class V1KeyParametersType {

  public static class EcParametersType {

    private final List<DescribableOid> curves;

    public EcParametersType(List<DescribableOid> curves) {
      this.curves = curves;
    }

    public List<DescribableOid> getCurves() {
      return curves;
    }

    public static EcParametersType parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("curves");
      List<DescribableOid> curves = (list == null) ? null
          : DescribableOid.parseList(list);
      return new EcParametersType(curves);
    }

  } // class EcParametersType

  public static class RsaParametersType {

    private final List<Integer> modulus;

    public List<Integer> getModulus() {
      return modulus;
    }

    public RsaParametersType(List<Integer> modulus) {
      this.modulus = modulus;
    }

    public static RsaParametersType parse(JsonMap json) throws CodecException {
      JsonList list = json.getList("modulus");
      if (list != null) {
        return new RsaParametersType(list.toIntList());
      }

      list = json.getList("modulusLengths");
      if (list != null) {
        List<V1Range> modulusLengths = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          modulusLengths.add(V1Range.parse(v));
        }

        List<Integer> modulus = new LinkedList<>();
        for (V1Range r : modulusLengths) {
          for (int i = r.getMin(); i < r.getMax(); i++) {
            modulus.add(i);
          }
        }

        return new RsaParametersType(modulus);
      } else {
        return new RsaParametersType(null);
      }
    }

  } // class RsaParametersType

  private EcParametersType ec;

  private RsaParametersType rsa;

  public EcParametersType getEc() {
    return ec;
  }

  public RsaParametersType getRsa() {
    return rsa;
  }

  public static V1KeyParametersType parse(JsonMap json)
      throws CodecException {
    V1KeyParametersType ret = new V1KeyParametersType();
    JsonMap map = json.getMap("ec");
    if (map != null) {
      ret.ec = EcParametersType.parse(json);
    }

    map = json.getMap("rsa");
    if (map != null) {
      ret.rsa = RsaParametersType.parse(map);
    }

    return ret;
  }

}
