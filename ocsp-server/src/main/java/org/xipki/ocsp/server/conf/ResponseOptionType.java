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

package org.xipki.ocsp.server.conf;

import org.xipki.ocsp.server.conf.OcspserverType.EmbedCertsMode;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class ResponseOptionType extends ValidatableConf {

  private boolean responderIdByName = true;

  private boolean includeInvalidityDate = false;

  private boolean includeRevReason = false;

  private EmbedCertsMode embedCertsMode = EmbedCertsMode.SIGNER;

  private boolean includeCerthash = false;

  private Long cacheMaxAge;

  private String name;

  public boolean isResponderIdByName() {
    return responderIdByName;
  }

  public void setResponderIdByName(boolean responderIdByName) {
    this.responderIdByName = responderIdByName;
  }

  public boolean isIncludeInvalidityDate() {
    return includeInvalidityDate;
  }

  public void setIncludeInvalidityDate(boolean includeInvalidityDate) {
    this.includeInvalidityDate = includeInvalidityDate;
  }

  public boolean isIncludeRevReason() {
    return includeRevReason;
  }

  public void setIncludeRevReason(boolean includeRevReason) {
    this.includeRevReason = includeRevReason;
  }

  public EmbedCertsMode getEmbedCertsMode() {
    return embedCertsMode;
  }

  public void setEmbedCertsMode(EmbedCertsMode embedCertsMode) {
    this.embedCertsMode = embedCertsMode;
  }

  public boolean isIncludeCerthash() {
    return includeCerthash;
  }

  public void setIncludeCerthash(boolean includeCerthash) {
    this.includeCerthash = includeCerthash;
  }

  public Long getCacheMaxAge() {
    return cacheMaxAge;
  }

  public void setCacheMaxAge(Long cacheMaxAge) {
    this.cacheMaxAge = cacheMaxAge;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(name, "name");
  }

}
