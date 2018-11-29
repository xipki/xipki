/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.cmpclient.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CmpclientType extends ValidatableConf {

  private List<SslType> ssls;

  private List<RequestorType> requestors;

  private List<ResponderType> responders;

  /**
   * Interval in minutes to update the CA information if autoconf is activated,
   * default to be 10, value between 1 and 4 will be converted to 5, value less than 1
   * disables the interval update
   */
  private Integer cainfoUpdateInterval;

  private List<CaType> cas;

  public List<SslType> getSsls() {
    if (ssls == null) {
      ssls = new LinkedList<>();
    }
    return ssls;
  }

  public void setSsls(List<SslType> ssls) {
    this.ssls = ssls;
  }

  public List<RequestorType> getRequestors() {
    if (requestors == null) {
      requestors = new LinkedList<>();
    }
    return requestors;
  }

  public void setRequestors(List<RequestorType> requestors) {
    this.requestors = requestors;
  }

  public List<ResponderType> getResponders() {
    if (responders == null) {
      responders = new LinkedList<>();
    }
    return responders;
  }

  public void setResponders(List<ResponderType> responders) {
    this.responders = responders;
  }

  public Integer getCainfoUpdateInterval() {
    return cainfoUpdateInterval;
  }

  public void setCainfoUpdateInterval(Integer cainfoUpdateInterval) {
    this.cainfoUpdateInterval = cainfoUpdateInterval;
  }

  public List<CaType> getCas() {
    if (cas == null) {
      cas = new LinkedList<>();
    }
    return cas;
  }

  public void setCas(List<CaType> cas) {
    this.cas = cas;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(ssls);
    notEmpty(requestors, "requestors");
    validate(requestors);
    notEmpty(responders, "responders");
    validate(responders);
    notEmpty(cas, "cas");
    validate(cas);
  }

}
