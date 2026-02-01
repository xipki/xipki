// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrBinary;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class SignerConf {

  private final List<FileOrBinary> certs;

  private final String type;

  private final String conf;

  public SignerConf(String type, String conf, List<FileOrBinary> certs) {
    this.type = Args.notBlank(type, "type");
    this.conf = Args.notBlank(conf, "conf");
    this.certs = certs;
  }

  public List<FileOrBinary> certs() {
    return certs;
  }

  public String type() {
      return type;
  }

  public String conf() {
    return conf;
  }

  public static SignerConf parse(JsonMap json) throws CodecException {
    return new SignerConf(json.getNnString("type"),
        json.getNnString("conf"),
        FileOrBinary.parseList(json.getList("certs")));
  }

}
