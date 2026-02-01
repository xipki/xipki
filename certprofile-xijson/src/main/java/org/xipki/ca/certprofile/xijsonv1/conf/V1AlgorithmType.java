// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 * Configuration of the signature algorithm of certificate.
 *
 * @author Lijun Liao (xipki)
 */

public class V1AlgorithmType {

  private final List<DescribableOid> algorithms;

  private final V1KeyParametersType parameters;

  public V1AlgorithmType(List<DescribableOid> algorithms,
                         V1KeyParametersType parameters) {
    this.algorithms = Args.notEmpty(algorithms, "algorithms");
    this.parameters = parameters;
  }

  public List<DescribableOid> algorithms() {
    return algorithms;
  }

  public V1KeyParametersType parameters() {
    return parameters;
  }

  public static V1AlgorithmType parse(JsonMap json) throws CodecException {
    List<DescribableOid> algorithms = DescribableOid.parseList(
        json.getNnList("algorithms"));
    JsonMap map = json.getMap("parameters");
    V1KeyParametersType parameters = (map == null) ? null
        : V1KeyParametersType.parse(map);
    return new V1AlgorithmType(algorithms, parameters);
  }

}
