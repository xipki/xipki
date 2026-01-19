// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.ca.gateway.conf.CaNameSignersConf;
import org.xipki.ca.gateway.conf.PopControlConf;
import org.xipki.ca.gateway.conf.ProtocolConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;

import java.nio.file.Paths;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class CmpProtocolConf extends ProtocolConf {

  private final CmpControlConf cmp;

  private final String authenticator;

  /**
   * The signers.
   */
  private final CaNameSignersConf signers;

  public CmpProtocolConf(Boolean logReqResp, PopControlConf pop,
                         SdkClientConf sdkClient, CmpControlConf cmp,
                         String authenticator, CaNameSignersConf signers) {
    super(logReqResp, pop, sdkClient);
    this.cmp = Args.notNull(cmp, "cmp");
    this.authenticator = Args.notBlank(authenticator, "authenticator");
    this.signers = signers;
  }

  public CmpControlConf getCmp() {
    return cmp;
  }

  public String getAuthenticator() {
    return authenticator;
  }

  public CaNameSignersConf getSigners() {
    return signers;
  }

  public static CmpProtocolConf parse(JsonMap json)
      throws CodecException, InvalidConfException {
    ProtocolConf pConf = ProtocolConf.parse0(json);

    JsonMap map = json.getMap("cmp");
    CmpControlConf cmp = (map == null) ? null
        : CmpControlConf.parse(map);

    map = json.getMap("signers");
    CaNameSignersConf signers = (map == null) ? null
        : CaNameSignersConf.parse(map);

    return new CmpProtocolConf(pConf.getLogReqResp(),
        pConf.getPop(), pConf.getSdkClient(), cmp,
        json.getString("authenticator"), signers);
  }

  public static CmpProtocolConf readConfFromFile(String fileName)
      throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException(
          "error parsing CmpProtocolConf: " + e.getMessage(), e);
    }
  }

}
