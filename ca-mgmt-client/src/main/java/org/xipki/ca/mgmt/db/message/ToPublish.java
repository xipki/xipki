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

package org.xipki.ca.mgmt.db.message;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ToPublish extends ValidatableConf {

  private int pubId;

  private long certId;

  private int caId;

  public int getPubId() {
    return pubId;
  }

  public void setPubId(int pubId) {
    this.pubId = pubId;
  }

  public long getCertId() {
    return certId;
  }

  public void setCertId(long certId) {
    this.certId = certId;
  }

  public int getCaId() {
    return caId;
  }

  public void setCaId(int caId) {
    this.caId = caId;
  }

  @Override
  public void validate() throws InvalidConfException {
  }

}
