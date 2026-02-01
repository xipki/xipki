// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

/**
 *
 * @author Lijun Liao (xipki)
 */

public class ProtocolConf {

  private final Boolean logReqResp;

  private final PopControlConf pop;

  private final SdkClientConf sdkClient;

  public ProtocolConf(Boolean logReqResp, PopControlConf pop,
                      SdkClientConf sdkClient) {
    this.logReqResp = logReqResp;
    this.pop = pop;
    this.sdkClient = sdkClient;
  }

  public Boolean logReqResp() {
    return logReqResp;
  }

  public PopControlConf pop() {
    return pop;
  }

  public SdkClientConf sdkClient() {
    return sdkClient;
  }

  public static ProtocolConf parse0(JsonMap json) throws CodecException {
    Boolean logReqResp = json.getBool("logReqResp");
    JsonMap map = json.getMap("pop");
    PopControlConf pop = (map == null) ? null : PopControlConf.parse(map);
    map = json.getMap("sdkClient");
    SdkClientConf sdkClientConf = (map == null) ? null
        : SdkClientConf.parse(map);
    return new ProtocolConf(logReqResp, pop, sdkClientConf);
  }

}
