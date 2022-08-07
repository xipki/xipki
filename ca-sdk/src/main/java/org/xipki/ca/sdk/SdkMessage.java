package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public abstract class SdkMessage {

  public byte[] getEncoded() {
    return JSON.toJSONBytes(this);
  }

}
