// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 * Extension CCC Instance CA ExtensionSchema.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class CCCInstanceCAExtensionSchema extends CCCSimpleExtensionSchema {

  private final long appletVersion;

  private byte[] platformInformation;

  public CCCInstanceCAExtensionSchema(int version, long appletVersion) {
    super(version);
    this.appletVersion = Args.range(appletVersion, "appletVersion",
    1, 0xFFFFFFFFL);
  }

  public long getAppletVersion() {
    return appletVersion;
  }

  public byte[] getPlatformInformation() {
    return platformInformation;
  }

  public void setPlatformInformation(byte[] platformInformation) {
    this.platformInformation = platformInformation;
  }

  public JsonMap toCodec() {
    return super.toCodec().put("appletVersion", appletVersion)
        .put("platformInformation", platformInformation);
  }

  public static CCCInstanceCAExtensionSchema parse(JsonMap json)
      throws CodecException {
    CCCInstanceCAExtensionSchema ret = new CCCInstanceCAExtensionSchema(
        json.getNnInt("version"), json.getNnInt("appletVersion"));
    ret.setPlatformInformation(json.getBytes("platformInformation"));
    return ret;
  }

}
