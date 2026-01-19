// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CaNameSignersConf {

  private final SignerConf default_;

  private final List<CaNameSignerConf> signers;

  public CaNameSignersConf(SignerConf default_,
                           List<CaNameSignerConf> signers) {
    this.default_ = default_;
    this.signers = signers;
  }

  public SignerConf getDefault() {
    return default_;
  }

  public List<CaNameSignerConf> getSigners() {
    return signers;
  }

  public static CaNameSignersConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("default");
    SignerConf default_ = (map == null) ? null : SignerConf.parse(map);
    JsonList list = json.getList("signers");
    List<CaNameSignerConf> signers = null;
    if (list != null) {
      signers = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        signers.add(CaNameSignerConf.parse(v));
      }
    }

    return new CaNameSignersConf(default_, signers);
  }

}
