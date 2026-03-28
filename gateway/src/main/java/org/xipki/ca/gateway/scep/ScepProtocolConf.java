// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.scep;

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
 * SCEP Protocol Conf configuration.
 */

public class ScepProtocolConf extends GatewayConf.ProtocolConf {

  private final ScepControl scep;

  private final String authenticator;

  private final List<GatewayConf.CaProfileConf> caProfiles;

  /**
   * The signers.
   */
  private final GatewayConf.CaNameSignersConf signers;

  public ScepProtocolConf(
      Boolean logReqResp, GatewayConf.PopControlConf pop, SdkClientConf sdkClient,
      ScepControl scep, String authenticator, List<GatewayConf.CaProfileConf> caProfiles,
      GatewayConf.CaNameSignersConf signers) {
    super(logReqResp, pop, sdkClient);
    this.scep = Args.notNull(scep, "scep");
    this.authenticator = Args.notBlank(authenticator, "authenticator");
    this.caProfiles = caProfiles;
    this.signers = Args.notNull(signers, "signers");
    if (caProfiles != null) {
      try {
        new GatewayConf.CaProfilesControl(caProfiles);
      } catch (InvalidConfException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  public ScepControl scep() {
    return scep;
  }

  public String authenticator() {
    return authenticator;
  }

  public List<GatewayConf.CaProfileConf> caProfiles() {
    return caProfiles;
  }

  public GatewayConf.CaNameSignersConf signers() {
    return signers;
  }

  public static ScepProtocolConf parse(JsonMap json) throws CodecException {
    GatewayConf.ProtocolConf pConf = GatewayConf.ProtocolConf.parse0(json);

    JsonMap map = json.getMap("scep");
    ScepControl scep = (map == null) ? null : ScepControl.parse(map);

    JsonList list = json.getList("caProfiles");
    List<GatewayConf.CaProfileConf> caProfiles = null;
    if (list != null) {
      caProfiles = new ArrayList<>(list.size());
      for (JsonMap v : list.toMapList()) {
        caProfiles.add(GatewayConf.CaProfileConf.parse(v));
      }
    }

    map = json.getMap("signers");
    GatewayConf.CaNameSignersConf signers = (map == null) ? null
        : GatewayConf.CaNameSignersConf.parse(map);

    return new ScepProtocolConf(pConf.logReqResp(), pConf.pop(),
        pConf.sdkClient(), scep, json.getString("authenticator"), caProfiles, signers);
  }

  public static ScepProtocolConf readConfFromFile(String fileName) throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException("error parsing ScepProtocolConf: " + e.getMessage(), e);
    }
  }

}
