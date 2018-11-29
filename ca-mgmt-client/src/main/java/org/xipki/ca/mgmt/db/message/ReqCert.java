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

import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class ReqCert extends IdentifidDbObject {

  public static class ReqCerts extends ValidatableConf {

    private List<ReqCert> reqCerts;

    public List<ReqCert> getReqCerts() {
      if (reqCerts == null) {
        reqCerts = new LinkedList<>();
      }
      return reqCerts;
    }

    public void setReqCerts(List<ReqCert> reqCerts) {
      this.reqCerts = reqCerts;
    }

    public void add(ReqCert reqCert) {
      if (reqCerts == null) {
        reqCerts = new LinkedList<>();
      }
      reqCerts.add(reqCert);
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(reqCerts);
    }

  }

  private Long rid;

  private Long cid;

  public Long getRid() {
    return rid;
  }

  public void setRid(long rid) {
    this.rid = rid;
  }

  public Long getCid() {
    return cid;
  }

  public void setCid(long cid) {
    this.cid = cid;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(rid, "rid");
    notNull(cid, "cid");
  }

}
