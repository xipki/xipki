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

package org.xipki.qa.ca;

import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.exception.InvalidConfException;
import org.xipki.util.ValidatableConf;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration the QA system.
 *
 * @author Lijun Liao
 */
public class QaconfType extends ValidatableConf {

  public static class Certprofile extends FileOrValue {

    private String name;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      super.validate();
      notBlank(name, "name");
    }

  } // class class

  public static class Issuer extends ValidatableConf {

    private FileOrBinary cert;

    private String validityMode;

    private List<String> caIssuerUrls;

    private List<String> ocspUrls;

    private List<String> crlUrls;

    private List<String> deltaCrlUrls;

    private String name;

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary cert) {
      this.cert = cert;
    }

    public String getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(String validityMode) {
      this.validityMode = validityMode;
    }

    public List<String> getCaIssuerUrls() {
      if (caIssuerUrls == null) {
        caIssuerUrls = new LinkedList<>();
      }
      return caIssuerUrls;
    }

    public void setCaIssuerUrls(List<String> caIssuerUrls) {
      this.caIssuerUrls = caIssuerUrls;
    }

    public List<String> getOcspUrls() {
      if (ocspUrls == null) {
        ocspUrls = new LinkedList<>();
      }
      return ocspUrls;
    }

    public void setOcspUrls(List<String> ocspUrls) {
      this.ocspUrls = ocspUrls;
    }

    public List<String> getCrlUrls() {
      if (crlUrls == null) {
        crlUrls = new LinkedList<>();
      }
      return crlUrls;
    }

    public void setCrlUrls(List<String> crlUrls) {
      this.crlUrls = crlUrls;
    }

    public List<String> getDeltaCrlUrls() {
      if (deltaCrlUrls == null) {
        deltaCrlUrls = new LinkedList<>();
      }
      return deltaCrlUrls;
    }

    public void setDeltaCrlUrls(List<String> deltaCrlUrls) {
      this.deltaCrlUrls = deltaCrlUrls;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notNull(cert, "cert");
      validate(cert);
      notBlank(name, "name");
    }

  } // class Issuer

  private List<Issuer> issuers;

  private List<Certprofile> certprofiles;

  public List<Issuer> getIssuers() {
    if (issuers == null) {
      issuers = new LinkedList<>();
    }
    return issuers;
  }

  public void setIssuers(List<Issuer> issuers) {
    this.issuers = issuers;
  }

  public List<Certprofile> getCertprofiles() {
    if (certprofiles == null) {
      certprofiles = new LinkedList<>();
    }
    return certprofiles;
  }

  public void setCertprofiles(List<Certprofile> certprofiles) {
    this.certprofiles = certprofiles;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    validate(issuers);
    validate(certprofiles);
  }

}
