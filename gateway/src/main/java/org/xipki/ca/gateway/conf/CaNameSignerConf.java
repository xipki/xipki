// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class CaNameSignerConf {

  private final List<String> names;

  private final SignerConf signer;

  public CaNameSignerConf(SignerConf signer, List<String> names) {
    this.names  = names;
    this.signer = signer;
  }

  public List<String> names() {
    return names;
  }

  public SignerConf signer() {
    return signer;
  }

  public static CaNameSignerConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("signer");
    SignerConf signer = (map == null) ? null : SignerConf.parse(map);
    return new CaNameSignerConf(signer, json.getStringList("names"));
  }

}
