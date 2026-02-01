// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.certprofile.xijson.conf.extn.TlsFeature;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableInt;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension TlsFeature.
 *
 * @author Lijun Liao (xipki)
 */

public class V1TlsFeature {

  private final List<DescribableInt> features;

  public V1TlsFeature(List<DescribableInt> features) {
    this.features = Args.notEmpty(features, "features");
  }

  public TlsFeature toV2() {
    List<Integer> list = new ArrayList<>();
    for (DescribableInt feature : features) {
      list.add(feature.value());
    }

    return new TlsFeature(list);
  }

  public static V1TlsFeature parse(JsonMap json) throws CodecException {
    return new V1TlsFeature(DescribableInt.parseList(
        json.getNnList("features")));
  }

}
