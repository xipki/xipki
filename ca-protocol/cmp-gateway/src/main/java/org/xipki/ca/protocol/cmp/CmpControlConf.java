/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.protocol.cmp;

import java.util.List;

/**
 * CMP control configuration.
 *
 * @author Lijun Liao
 * @since 6.0.0
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

  public Boolean getConfirmCert() {
    return confirmCert;
  }

  public void setConfirmCert(Boolean confirmCert) {
    this.confirmCert = confirmCert;
  }

  public Boolean getSendCaCert() {
    return sendCaCert;
  }

  public void setSendCaCert(Boolean sendCaCert) {
    this.sendCaCert = sendCaCert;
  }

  public Boolean getSendCertChain() {
    return sendCertChain;
  }

  public void setSendCertChain(Boolean sendCertChain) {
    this.sendCertChain = sendCertChain;
  }

  public Boolean getMessageTimeRequired() {
    return messageTimeRequired;
  }

  public void setMessageTimeRequired(Boolean messageTimeRequired) {
    this.messageTimeRequired = messageTimeRequired;
  }

  public Boolean getSendResponderCert() {
    return sendResponderCert;
  }

  public void setSendResponderCert(Boolean sendResponderCert) {
    this.sendResponderCert = sendResponderCert;
  }

  public Integer getMessageTimeBias() {
    return messageTimeBias;
  }

  public void setMessageTimeBias(Integer messageTimeBias) {
    this.messageTimeBias = messageTimeBias;
  }

  public Integer getConfirmWaitTime() {
    return confirmWaitTime;
  }

  public void setConfirmWaitTime(Integer confirmWaitTime) {
    this.confirmWaitTime = confirmWaitTime;
  }

  public String getResponsePbmOwf() {
    return responsePbmOwf;
  }

  public void setResponsePbmOwf(String responsePbmOwf) {
    this.responsePbmOwf = responsePbmOwf;
  }

  public List<String> getRequestPbmOwfs() {
    return requestPbmOwfs;
  }

  public void setRequestPbmOwfs(List<String> requestPbmOwfs) {
    this.requestPbmOwfs = requestPbmOwfs;
  }

  public String getResponsePbmMac() {
    return responsePbmMac;
  }

  public void setResponsePbmMac(String responsePbmMac) {
    this.responsePbmMac = responsePbmMac;
  }

  public List<String> getRequestSigAlgos() {
    return requestSigAlgos;
  }

  public void setRequestSigAlgos(List<String> requestSigAlgos) {
    this.requestSigAlgos = requestSigAlgos;
  }

  public List<String> getRequestPbmMacs() {
    return requestPbmMacs;
  }

  public void setRequestPbmMacs(List<String> requestPbmMacs) {
    this.requestPbmMacs = requestPbmMacs;
  }

  public Integer getResponsePbmIterationCount() {
    return responsePbmIterationCount;
  }

  public void setResponsePbmIterationCount(Integer responsePbmIterationCount) {
    this.responsePbmIterationCount = responsePbmIterationCount;
  }

}
