// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.type.KeystoreConf;

import java.util.List;

/**
 * POP (proof-of-possession) control configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class PopControlConf {

  private final List<String> sigAlgos;

  private final KeystoreConf dh;

  private final KeystoreConf kem;

  public PopControlConf(List<String> sigAlgos, KeystoreConf dh,
                        KeystoreConf kem) {
    this.sigAlgos = sigAlgos;
    this.dh = dh;
    this.kem = kem;
  }

  public List<String> sigAlgos() {
    return this.sigAlgos;
  }

  public KeystoreConf dh() {
    return this.dh;
  }

  public KeystoreConf kem() {
    return this.kem;
  }

  public static PopControlConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("dh");
    KeystoreConf dh = (map == null) ? null : KeystoreConf.parse(map);

    map = json.getMap("kem");
    KeystoreConf kem = (map == null) ? null : KeystoreConf.parse(map);
    return new PopControlConf(json.getStringList("sigAlgos"), dh, kem);
  }

}
