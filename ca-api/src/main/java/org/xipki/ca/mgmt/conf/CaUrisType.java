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

package org.xipki.ca.mgmt.conf;

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CaUrisType extends ValidatableConf {

  private List<String> cacertUris;

  private List<String> crlUris;

  private List<String> deltacrlUris;

  private List<String> ocspUris;

  public List<String> getCacertUris() {
    if (cacertUris == null) {
      cacertUris = new LinkedList<>();
    }
    return cacertUris;
  }

  public void setCacertUris(List<String> cacertUris) {
    this.cacertUris = cacertUris;
  }

  public List<String> getCrlUris() {
    if (crlUris == null) {
      crlUris = new LinkedList<>();
    }
    return crlUris;
  }

  public void setCrlUris(List<String> crlUris) {
    this.crlUris = crlUris;
  }

  public List<String> getDeltacrlUris() {
    if (deltacrlUris == null) {
      deltacrlUris = new LinkedList<>();
    }
    return deltacrlUris;
  }

  public void setDeltacrlUris(List<String> deltacrlUris) {
    this.deltacrlUris = deltacrlUris;
  }

  public List<String> getOcspUris() {
    if (ocspUris == null) {
      ocspUris = new LinkedList<>();
    }
    return ocspUris;
  }

  public void setOcspUris(List<String> ocspUris) {
    this.ocspUris = ocspUris;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
