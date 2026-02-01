// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.ca.gateway.conf;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 * Gateway's CA-Profile Map.
 *
 * @author Lijun Liao (xipki)
 */
public class CaProfileConf {

  private final String name;

  private final String ca;

  private final String certprofile;

  public CaProfileConf(String name, String ca, String certprofile) {
    this.name = Args.toNonBlankLower(name, "name");
    this.ca = Args.notBlank(ca, "ca");
    this.certprofile = Args.notBlank(certprofile, "certprofile");
  }

  public String name() {
    return name;
  }

  public String ca() {
    return ca;
  }

  public String certprofile() {
    return certprofile;
  }

  public static CaProfileConf parse(JsonMap json) throws CodecException {
    return new CaProfileConf(json.getNnString("name"),
        json.getNnString("ca"), json.getNnString("certprofile"));
  }

}
