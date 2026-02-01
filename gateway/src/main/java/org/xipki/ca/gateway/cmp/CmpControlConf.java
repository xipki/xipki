// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.util.List;

/**
 * CMP control configuration.
 *
 * @author Lijun Liao (xipki)
 */

public class CmpControlConf {

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
    ret.setResponsePbmIterationCount(
        json.getInt("responsePbmIterationCount"));
    return ret;
  }

}
