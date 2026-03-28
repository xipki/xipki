// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.ca.gateway.GatewayConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;

import java.nio.file.Paths;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * CMP Protocol Conf configuration.
 */

public class CmpProtocolConf extends GatewayConf.ProtocolConf {

  private final CmpControlConf cmp;

  private final String authenticator;

  /**
   * The signers.
   */
  private final GatewayConf.CaNameSignersConf signers;

  public CmpProtocolConf(
      Boolean logReqResp, GatewayConf.PopControlConf pop, SdkClientConf sdkClient,
      CmpControlConf cmp, String authenticator, GatewayConf.CaNameSignersConf signers) {
    super(logReqResp, pop, sdkClient);
    this.cmp = Args.notNull(cmp, "cmp");
    this.authenticator = Args.notBlank(authenticator, "authenticator");
    this.signers = signers;
  }

  public CmpControlConf cmp() {
    return cmp;
  }

  public String authenticator() {
    return authenticator;
  }

  public GatewayConf.CaNameSignersConf signers() {
    return signers;
  }

  public static CmpProtocolConf parse(JsonMap json) throws CodecException {
    GatewayConf.ProtocolConf pConf = GatewayConf.ProtocolConf.parse0(json);

    JsonMap map = json.getMap("cmp");
    CmpControlConf cmp = (map == null) ? null : CmpControlConf.parse(map);

    map = json.getMap("signers");
    GatewayConf.CaNameSignersConf signers = (map == null) ? null
        : GatewayConf.CaNameSignersConf.parse(map);

    return new CmpProtocolConf(pConf.logReqResp(), pConf.pop(), pConf.sdkClient(), cmp,
        json.getString("authenticator"), signers);
  }

  public static CmpProtocolConf readConfFromFile(String fileName) throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException("error parsing CmpProtocolConf: " + e.getMessage(), e);
    }
  }

  /**
   * CMP Control Conf configuration.
   *
   * @author Lijun Liao (xipki)
   */

  public static class CmpControlConf {

    private Boolean confirmCert;

    private Boolean sendCaCert;

    private Boolean sendCertChain;

    private Boolean messageTimeRequired;

    private Boolean sendResponderCert;

    private Integer messageTimeBias;

    private Integer confirmWaitTime;

    private List<String> requestSigAlgos;

    private List<String> requestPbmOwfs;

    private List<String> requestPbmMacs;

    private String responsePbmMac;

    private String responsePbmOwf;

    private Integer responsePbmIterationCount;

    public Boolean confirmCert() {
      return confirmCert;
    }

    public void setConfirmCert(Boolean confirmCert) {
      this.confirmCert = confirmCert;
    }

    public Boolean sendCaCert() {
      return sendCaCert;
    }

    public void setSendCaCert(Boolean sendCaCert) {
      this.sendCaCert = sendCaCert;
    }

    public Boolean sendCertChain() {
      return sendCertChain;
    }

    public void setSendCertChain(Boolean sendCertChain) {
      this.sendCertChain = sendCertChain;
    }

    public Boolean messageTimeRequired() {
      return messageTimeRequired;
    }

    public void setMessageTimeRequired(Boolean messageTimeRequired) {
      this.messageTimeRequired = messageTimeRequired;
    }

    public Boolean sendResponderCert() {
      return sendResponderCert;
    }

    public void setSendResponderCert(Boolean sendResponderCert) {
      this.sendResponderCert = sendResponderCert;
    }

    public Integer messageTimeBias() {
      return messageTimeBias;
    }

    public void setMessageTimeBias(Integer messageTimeBias) {
      this.messageTimeBias = messageTimeBias;
    }

    public Integer confirmWaitTime() {
      return confirmWaitTime;
    }

    public void setConfirmWaitTime(Integer confirmWaitTime) {
      this.confirmWaitTime = confirmWaitTime;
    }

    public String responsePbmOwf() {
      return responsePbmOwf;
    }

    public void setResponsePbmOwf(String responsePbmOwf) {
      this.responsePbmOwf = responsePbmOwf;
    }

    public List<String> requestPbmOwfs() {
      return requestPbmOwfs;
    }

    public void setRequestPbmOwfs(List<String> requestPbmOwfs) {
      this.requestPbmOwfs = requestPbmOwfs;
    }

    public String responsePbmMac() {
      return responsePbmMac;
    }

    public void setResponsePbmMac(String responsePbmMac) {
      this.responsePbmMac = responsePbmMac;
    }

    public List<String> requestSigAlgos() {
      return requestSigAlgos;
    }

    public void setRequestSigAlgos(List<String> requestSigAlgos) {
      this.requestSigAlgos = requestSigAlgos;
    }

    public List<String> requestPbmMacs() {
      return requestPbmMacs;
    }

    public void setRequestPbmMacs(List<String> requestPbmMacs) {
      this.requestPbmMacs = requestPbmMacs;
    }

    public Integer responsePbmIterationCount() {
      return responsePbmIterationCount;
    }

    public void setResponsePbmIterationCount(Integer responsePbmIterationCount) {
      this.responsePbmIterationCount = responsePbmIterationCount;
    }

    public static CmpControlConf parse(JsonMap json) throws CodecException {
      CmpControlConf ret = new CmpControlConf();
      ret.setConfirmCert(json.getBool("confirmCert"));
      ret.setSendCaCert (json.getBool("sendCaCert"));
      ret.setSendCertChain(json.getBool("sendCertChain"));
      ret.setMessageTimeRequired(json.getBool("messageTimeRequired"));
      ret.setSendResponderCert(json.getBool("sendResponderCert"));
      ret.setMessageTimeBias(json.getInt("messageTimeBias"));
      ret.setConfirmWaitTime(json.getInt("confirmWaitTime"));
      ret.setRequestSigAlgos(json.getStringList("requestSigAlgos"));
      ret.setRequestPbmOwfs(json.getStringList("requestPbmOwfs"));
      ret.setRequestPbmMacs(json.getStringList("requestPbmMacs"));
      ret.setResponsePbmMac(json.getString("responsePbmMac"));
      ret.setResponsePbmOwf(json.getString("responsePbmOwf"));
      ret.setResponsePbmIterationCount(json.getInt("responsePbmIterationCount"));
      return ret;
    }

  }
}
