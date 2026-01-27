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
 * @since 6.4.0
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

  public String getName() {
    return name;
  }

  public String getCa() {
    return ca;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public static CaProfileConf parse(JsonMap json) throws CodecException {
    return new CaProfileConf(json.getNnString("name"),
        json.getNnString("ca"), json.getNnString("certprofile"));
  }

}
