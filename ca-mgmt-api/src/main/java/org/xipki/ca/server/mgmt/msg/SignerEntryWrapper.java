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

package org.xipki.ca.server.mgmt.msg;

import org.xipki.ca.server.mgmt.api.SignerEntry;
import org.xipki.util.Base64;

/**
 * TODO.
 * @author Lijun Liao
 */

public class SignerEntryWrapper {

  private String name;

  private String type;

  private String conf;

  private byte[] encodedCert;

  private boolean faulty;

  public SignerEntryWrapper() {
  }

  public SignerEntryWrapper(SignerEntry signerEntry) {
    this.name = signerEntry.getName();
    this.type = signerEntry.getType();
    this.conf = signerEntry.getConf();
    this.faulty = signerEntry.isFaulty();
    if (signerEntry.getBase64Cert() != null) {
      this.encodedCert = Base64.decode(signerEntry.getBase64Cert());
    }
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public void setConf(String conf) {
    this.conf = conf;
  }

  public byte[] getEncodedCert() {
    return encodedCert;
  }

  public void setEncodedCert(byte[] encodedCert) {
    this.encodedCert = encodedCert;
  }

  public String getConf() {
    return conf;
  }

  public boolean isFaulty() {
    return faulty;
  }

  public void setFaulty(boolean faulty) {
    this.faulty = faulty;
  }

  public SignerEntry toSignerEntry() {
    String base64Cert = null;
    if (encodedCert != null) {
      base64Cert = Base64.encodeToString(encodedCert);
    }

    SignerEntry ret = new SignerEntry(name, type, conf, base64Cert);
    ret.setConfFaulty(faulty);
    return ret;
  }
}
