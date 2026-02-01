// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 * Extension TlsFeature.
 *
 * @author Lijun Liao (xipki)
 */

public class TlsFeature implements JsonEncodable {

  private final List<Integer> features;

  public TlsFeature(List<Integer> features) {
    Args.notEmpty(features, "features");
    for (int feature : features) {
      if (feature < 0 || feature > 65535) {
        throw new IllegalArgumentException(
            "feature non in [0, 65535]: " + feature);
      }
    }

    this.features = features;
  }

  public List<Integer> features() {
    return features;
  }

  @Override
  public JsonMap toCodec() {
    JsonList list = new JsonList();
    for (Integer i : features) {
      list.add(i);
    }
    return new JsonMap().put("features", list);
  }

  public static TlsFeature parse(JsonMap json) throws CodecException {
    List<Integer> features = json.getNnList("features").toIntList();
    return new TlsFeature(features);
  }

} // class TlsFeature
