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

import java.util.LinkedList;
import java.util.List;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class Crl extends IdentifidDbObject {

  public static class Crls extends ValidatableConf {

    private List<Crl> crls;

    public List<Crl> getCrls() {
      return crls;
    }

    public void setCrls(List<Crl> crls) {
      this.crls = crls;
    }

    public void add(Crl crl) {
      if (crls == null) {
        crls = new LinkedList<>();
      }
      crls.add(crl);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(crls);
    }

  }

  private Integer caId;

  private String crlNo;

  private String file;

  public Integer getCaId() {
    return caId;
  }

  public void setCaId(Integer caId) {
    this.caId = caId;
  }

  public String getCrlNo() {
    return crlNo;
  }

  public void setCrlNo(String crlNo) {
    this.crlNo = crlNo;
  }

  public String getFile() {
    return file;
  }

  public void setFile(String file) {
    this.file = file;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(caId, "caId");
    notEmpty(crlNo, "crlNo");
    notEmpty(file, "file");
  }

}
