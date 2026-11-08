// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.acme.AcmeConf;

import java.nio.file.Paths;

/**
 * ACME Protocol configuration.
 *
 * @author Lijun Liao (xipki)
 */
public class AcmeProtocolConf extends GatewayConf.ProtocolConf {

  private final AcmeConf.Acme acme;

  public AcmeProtocolConf(Boolean logReqResp, GatewayConf.PopControlConf pop,
                          SdkClientConf sdkClient, AcmeConf.Acme acme) {
    super(logReqResp, pop, sdkClient);
    this.acme = Args.notNull(acme, "acme");
  }

  public AcmeConf.Acme acme() {
    return acme;
  }

  public static AcmeProtocolConf parse(JsonMap json) throws CodecException, InvalidConfException {
    JsonMap confJson = json.getMap("acme");
    if (confJson == null) {
      confJson = json;
    }

    GatewayConf.ProtocolConf pConf = GatewayConf.ProtocolConf.parse0(confJson);

    AcmeConf.Acme acme = AcmeConf.Acme.parse(confJson);
    acme.validate();

    return new AcmeProtocolConf(pConf.logReqResp(), pConf.pop(), pConf.sdkClient(), acme);
  }

  public static AcmeProtocolConf readConfFromFile(String fileName) throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException("error parsing AcmeProtocolConf: " + e.getMessage(), e);
    }
  }

}
