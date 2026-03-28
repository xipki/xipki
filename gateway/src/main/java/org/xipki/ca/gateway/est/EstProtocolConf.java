// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.est;

import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * Est Protocol Conf configuration.
 */

public class EstProtocolConf extends GatewayConf.ProtocolConf {

  private final String authenticator;

  private final List<GatewayConf.CaProfileConf> caProfiles;

  public EstProtocolConf(
      Boolean logReqResp, GatewayConf.PopControlConf pop, SdkClientConf sdkClient,
      String authenticator, List<GatewayConf.CaProfileConf> caProfiles) {
    super(logReqResp, pop, sdkClient);
    this.authenticator = Args.notBlank(authenticator, "authenticator");
    this.caProfiles = caProfiles;
  }

  public String authenticator() {
    return authenticator;
  }

  public List<GatewayConf.CaProfileConf> caProfiles() {
    return caProfiles;
  }

  public static EstProtocolConf parse(JsonMap json) throws CodecException {
    GatewayConf.ProtocolConf pConf = GatewayConf.ProtocolConf.parse0(json);

    JsonList list = json.getList("caProfiles");
    List<GatewayConf.CaProfileConf> caProfiles = null;
    if (list != null) {
      caProfiles = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        caProfiles.add(GatewayConf.CaProfileConf.parse(v));
      }
    }

    return new EstProtocolConf(pConf.logReqResp(), pConf.pop(), pConf.sdkClient(),
        json.getString("authenticator"), caProfiles);
  }

  public static EstProtocolConf readConfFromFile(String fileName) throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException("error parsing EstProtocolConf: " + e.getMessage(), e);
    }
  }

}
