// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrBinary;

/**
 * Configuration of CMP client.
 *
 * @author Lijun Liao (xipki)
 */

public class OcspRequestorConf {

  private String signerType;

  private String signerConf;

  private FileOrBinary signerCert;

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signerType = signerType;
  }

  public String getSignerConf() {
    return signerConf;
  }

  public void setSignerConf(String signerConf) {
    this.signerConf = signerConf;
  }

  public FileOrBinary getSignerCert() {
    return signerCert;
  }

  public void setSignerCert(FileOrBinary signerCert) {
    this.signerCert = signerCert;
  }

  public static OcspRequestorConf parse(JsonMap json) throws CodecException {
    OcspRequestorConf ret = new OcspRequestorConf();
    ret.setSignerType(json.getString("signerType"));
    ret.setSignerConf(json.getString("signerConf"));
    ret.setSignerCert(FileOrBinary.parse(json.getMap("signerCert")));
    return ret;
  }
}
