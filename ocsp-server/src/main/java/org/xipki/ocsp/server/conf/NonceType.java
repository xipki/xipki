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

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class NonceType extends ValidatableConf {

  /**
   * valid values are forbidden, optional and required.
   */
  private String occurrence;

  private Integer minLen;

  private Integer maxLen;

  public String getOccurrence() {
    return occurrence;
  }

  public void setOccurrence(String occurrence) {
    this.occurrence = occurrence;
  }

  public Integer getMinLen() {
    return minLen;
  }

  public void setMinLen(Integer minLen) {
    this.minLen = minLen;
  }

  public Integer getMaxLen() {
    return maxLen;
  }

  public void setMaxLen(Integer maxLen) {
    this.maxLen = maxLen;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(occurrence, "occurrence");
  }

}
