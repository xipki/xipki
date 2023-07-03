// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.security.util.JSON;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class AcmeProxyConf extends ProtocolProxyConf {

  private int nonceNumBytes = 16;

  private int tokenNumBytes = 16;

  private String ca;

  private String tlsProfile;

  // optional. If not set, any valid email address will be accepted.
  // You can specify to the class name implementing org.xipki.ca.gateway.acme.ContactVerifier
  private String contactVerifier;

  private String baseUrl;

  private String termsOfService;

  private String website;

  private String[] caaIdentities;

  public String getBaseUrl() {
    if (baseUrl != null) {
      if (!baseUrl.endsWith("/")) {
        baseUrl += "/";
      }
    }

    return baseUrl;
  }

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getTlsProfile() {
    return tlsProfile;
  }

  public void setTlsProfile(String tlsProfile) {
    this.tlsProfile = tlsProfile;
  }

  public String getContactVerifier() {
    return contactVerifier;
  }

  public void setContactVerifier(String contactVerifier) {
    this.contactVerifier = contactVerifier;
  }

  public int getNonceNumBytes() {
    return nonceNumBytes;
  }

  public int getTokenNumBytes() {
    return tokenNumBytes;
  }

  public void setTokenNumBytes(int tokenNumBytes) {
    this.tokenNumBytes = tokenNumBytes;
  }

  public void setNonceNumBytes(int nonceNumBytes) {
    this.nonceNumBytes = nonceNumBytes;
  }

  public void setBaseUrl(String baseUrl) {
    this.baseUrl = baseUrl;
  }

  public String getTermsOfService() {
    return termsOfService;
  }

  public void setTermsOfService(String termsOfService) {
    this.termsOfService = termsOfService;
  }

  public String getWebsite() {
    return website;
  }

  public void setWebsite(String website) {
    this.website = website;
  }

  public String[] getCaaIdentities() {
    return caaIdentities;
  }

  public void setCaaIdentities(String[] caaIdentities) {
    this.caaIdentities = caaIdentities;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    if (nonceNumBytes < 12) {
      throw new InvalidConfException("nonceNumBytes must be not less than 12");
    }

    if (tokenNumBytes < 12) {
      throw new InvalidConfException("tokenNumBytes must be not less than 12");
    }

    if (baseUrl == null || baseUrl.length() == 0) {
      throw new InvalidConfException("baseUrl must be present and not blank.");
    }
  }

  public static AcmeProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      AcmeProxyConf conf = JSON.parseObject(is, AcmeProxyConf.class);
      conf.validate();
      return conf;
    }
  }

}
