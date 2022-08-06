package org.xipki.ca.sdk;

import com.alibaba.fastjson.JSON;

public abstract class SdkMessage {

  public byte[] getEncoded() {
    return JSON.toJSONBytes(this);
  }

}
