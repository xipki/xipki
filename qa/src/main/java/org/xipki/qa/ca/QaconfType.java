// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.ca;

import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Configuration the QA system.
 *
 * @author Lijun Liao (xipki)
 */
public class QaconfType extends ValidableConf {

  public static class Certprofile extends FileOrValue {

    private String name;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public void validate() throws InvalidConfException {
      super.validate();
      notBlank(name, "name");
    }

  } // class class

  public static class Issuer extends ValidableConf {

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
    public void validate() throws InvalidConfException {
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
  public void validate() throws InvalidConfException {
    validate(issuers, certprofiles);
  }

}
