// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.security.util.JSON;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class AcmeProxyConf extends ProtocolProxyConf {

  public static class CaProfile {

    private List<String> keyTypes;

    private String ca;

    private String tlsProfile;

    public List<String> getKeyTypes() {
      return keyTypes;
    }

    public void setKeyTypes(List<String> keyTypes) {
      this.keyTypes = keyTypes;
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

    public void validate() throws InvalidConfException {
      if (ca == null || ca.isEmpty()) {
        throw new InvalidConfException("ca must be present and not blank.");
      }

      if (tlsProfile == null || tlsProfile.isEmpty()) {
        throw new InvalidConfException("tlsProfile must be present and not blank.");
      }
    }

  }

  public static class Acme {

    private int cacheSize = 1000;

    private int nonceNumBytes = 16;

    private int tokenNumBytes = 16;

    private int syncDbSeconds = 60;

    private String dbConf;

    // optional. If not set, any valid email address will be accepted.
    // You can specify to the class name implementing org.xipki.ca.gateway.acme.ContactVerifier
    private String contactVerifier;

    private String baseUrl;

    private String termsOfService;

    private String website;

    private List<String> caaIdentities;

    private CleanupOrderConf cleanupOrder;

    private List<CaProfile> caProfiles;

    private List<String> challengeTypes;

    public String getBaseUrl() {
      if (baseUrl != null) {
        if (!baseUrl.endsWith("/")) {
          baseUrl += "/";
        }
      }

      return baseUrl;
    }

    public int getSyncDbSeconds() {
      return syncDbSeconds;
    }

    public void setSyncDbSeconds(int syncDbSeconds) {
      this.syncDbSeconds = syncDbSeconds;
    }

    public int getCacheSize() {
      return cacheSize;
    }

    public void setCacheSize(int cacheSize) {
      this.cacheSize = cacheSize;
    }

    public String getDbConf() {
      return dbConf;
    }

    public void setDbConf(String dbConf) {
      this.dbConf = dbConf;
    }

    public List<CaProfile> getCaProfiles() {
      return caProfiles;
    }

    public void setCaProfiles(List<CaProfile> caProfiles) {
      this.caProfiles = caProfiles;
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

    public CleanupOrderConf getCleanupOrder() {
      return cleanupOrder;
    }

    public void setCleanupOrder(CleanupOrderConf cleanupOrder) {
      this.cleanupOrder = cleanupOrder;
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

    public List<String> getCaaIdentities() {
      return caaIdentities;
    }

    public void setCaaIdentities(List<String> caaIdentities) {
      this.caaIdentities = caaIdentities;
    }

    public List<String> getChallengeTypes() {
      return challengeTypes;
    }

    public void setChallengeTypes(List<String> challengeTypes) {
      this.challengeTypes = challengeTypes;
    }

    private void validate() throws InvalidConfException {
      if ((syncDbSeconds < 1)) {
        throw new InvalidConfException("syncDbSeconds must be not less than 1");
      }

      if (nonceNumBytes < 12) {
        throw new InvalidConfException("nonceNumBytes must be not less than 12");
      }

      if (tokenNumBytes < 12) {
        throw new InvalidConfException("tokenNumBytes must be not less than 12");
      }

      if (baseUrl == null || baseUrl.length() == 0) {
        throw new InvalidConfException("baseUrl must be present and not blank.");
      }

      if (caProfiles == null || caProfiles.isEmpty()) {
        throw new InvalidConfException("profiles must be present and not empty.");
      } else {
        for (CaProfile entry : caProfiles) {
          entry.validate();
        }
      }
    }

  }

  private Acme acme;

  public Acme getAcme() {
    return acme;
  }

  public void setAcme(Acme acme) {
    this.acme = acme;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    if (acme == null) {
      throw new InvalidConfException("acme must be present.");
    } else {
      acme.validate();
    }
  }

  public static AcmeProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    AcmeProxyConf conf = JSON.parseObject(new File(fileName), AcmeProxyConf.class);
    conf.validate();
    return conf;
  }

  public static class CleanupOrderConf {

    private int expiredCertDays;

    private int expiredOrderDays;

    public int getExpiredCertDays() {
      return expiredCertDays;
    }

    public void setExpiredCertDays(int expiredCertDays) {
      this.expiredCertDays = expiredCertDays;
    }

    public int getExpiredOrderDays() {
      return expiredOrderDays;
    }

    public void setExpiredOrderDays(int expiredOrderDays) {
      this.expiredOrderDays = expiredOrderDays;
    }
  }
}
