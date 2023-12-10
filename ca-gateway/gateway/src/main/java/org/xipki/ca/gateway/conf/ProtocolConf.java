// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.conf;

import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.ValidableConf;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public abstract class ProtocolConf extends ValidableConf {

  private Boolean logReqResp;

  private PopControlConf pop;

  private SdkClientConf sdkClient;

  public Boolean getLogReqResp() {
    return logReqResp;
  }

  public void setLogReqResp(Boolean logReqResp) {
    this.logReqResp = logReqResp;
  }

  public PopControlConf getPop() {
    return pop;
  }

  public void setPop(PopControlConf pop) {
    this.pop = pop;
  }

  public SdkClientConf getSdkClient() {
    return sdkClient;
  }

  public void setSdkClient(SdkClientConf sdkClient) {
    this.sdkClient = sdkClient;
  }

}
