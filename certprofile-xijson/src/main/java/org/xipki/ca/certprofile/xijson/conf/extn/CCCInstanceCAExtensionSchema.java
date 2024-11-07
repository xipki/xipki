// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.util.exception.InvalidConfException;

/**
 * Extension CCC Instance CA ExtensionSchema.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CCCInstanceCAExtensionSchema extends CCCSimpleExtensionSchema {

  private long appletVersion;

  private byte[] platformInformation;

  public long getAppletVersion() {
    return appletVersion;
  }

  public void setAppletVersion(long appletVersion) {
    this.appletVersion = appletVersion;
  }

  public byte[] getPlatformInformation() {
    return platformInformation;
  }

  public void setPlatformInformation(byte[] platformInformation) {
    this.platformInformation = platformInformation;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    if (appletVersion < 1 || appletVersion > 0xFFFFFFFFL) {
      throw new InvalidConfException("appletVersion is not in the range [1, 0xFFFFFFFF]: " + appletVersion);
    }
  }

}
