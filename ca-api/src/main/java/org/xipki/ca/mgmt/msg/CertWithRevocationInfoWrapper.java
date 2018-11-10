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

package org.xipki.ca.mgmt.msg;

import java.security.cert.CertificateException;

import org.xipki.ca.mgmt.api.CertWithRevocationInfo;
import org.xipki.security.CertRevocationInfo;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CertWithRevocationInfoWrapper {

  private CertWithDbIdWrapper cert;

  private CertRevocationInfo revInfo;

  private String certprofile;

  public CertWithRevocationInfoWrapper() {
  }

  public CertWithRevocationInfoWrapper(CertWithRevocationInfo info) {
    this.cert = new CertWithDbIdWrapper(info.getCert());
    this.revInfo = info.getRevInfo();
    this.certprofile = info.getCertprofile();
  }

  public CertWithDbIdWrapper getCert() {
    return cert;
  }

  public void setCert(CertWithDbIdWrapper cert) {
    this.cert = cert;
  }

  public CertRevocationInfo getRevInfo() {
    return revInfo;
  }

  public void setRevInfo(CertRevocationInfo revInfo) {
    this.revInfo = revInfo;
  }

  public String getCertprofile() {
    return certprofile;
  }

  public void setCertprofile(String certprofile) {
    this.certprofile = certprofile;
  }

  public CertWithRevocationInfo toCertWithRevocationInfo() throws CertificateException {
    CertWithRevocationInfo ret = new CertWithRevocationInfo();
    ret.setCert(cert.toCertWithDbId());
    ret.setCertprofile(certprofile);
    ret.setRevInfo(revInfo);
    return ret;
  }

}
