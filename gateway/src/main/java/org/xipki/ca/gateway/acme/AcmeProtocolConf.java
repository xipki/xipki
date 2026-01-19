// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.xipki.ca.gateway.conf.PopControlConf;
import org.xipki.ca.gateway.conf.ProtocolConf;
import org.xipki.ca.sdk.SdkClientConf;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class AcmeProtocolConf extends ProtocolConf {

  private final Acme acme;

  public AcmeProtocolConf(Boolean logReqResp, PopControlConf pop,
                          SdkClientConf sdkClient, Acme acme) {
    super(logReqResp, pop, sdkClient);
    this.acme = Args.notNull(acme, "acme");
  }

  public Acme getAcme() {
    return acme;
  }

  public static AcmeProtocolConf parse(JsonMap json)
      throws CodecException, InvalidConfException {
    ProtocolConf pConf = ProtocolConf.parse0(json);

    Acme acme = Acme.parse(json);
    acme.validate();

    return new AcmeProtocolConf(pConf.getLogReqResp(),
        pConf.getPop(), pConf.getSdkClient(), acme);
  }

  public static AcmeProtocolConf readConfFromFile(String fileName)
      throws InvalidConfException {
    Args.notBlank(fileName, "fileName");

    try {
      return parse(JsonParser.parseMap(Paths.get(fileName), true));
    } catch (CodecException e) {
      throw new InvalidConfException(
          "error parsing AcmeProtocolConf: " + e.getMessage(), e);
    }
  }

  public static class CaProfile {

    private final List<String> keyTypes;

    private final String ca;

    private final String tlsProfile;

    public CaProfile(List<String> keyTypes, String ca, String tlsProfile) {
      this.keyTypes = keyTypes;
      this.ca = Args.notBlank(ca, "ca");
      this.tlsProfile = Args.notBlank(tlsProfile, "tlsProfile");
    }

    public List<String> getKeyTypes() {
      return keyTypes;
    }

    public String getCa() {
      return ca;
    }

    public String getTlsProfile() {
      return tlsProfile;
    }

    public static CaProfile parse(JsonMap json) throws CodecException {
      return new CaProfile(json.getStringList("keyTypes"),
          json.getNnString("ca"), json.getNnString("tlsProfile"));
    }

  }

  public static class Acme {

    private int cacheSize = 1000;

    private int nonceNumBytes = 16;

    private int tokenNumBytes = 16;

    private int syncDbSeconds = 60;

    private String dbConf;

    // optional. If not set, any valid email address will be accepted.
    // You can specify to the class name implementing
    // org.xipki.ca.gateway.acme.ContactVerifier
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
        throw new InvalidConfException(
            "nonceNumBytes must be not less than 12");
      }

      if (tokenNumBytes < 12) {
        throw new InvalidConfException(
            "tokenNumBytes must be not less than 12");
      }

      if (baseUrl == null || baseUrl.isEmpty()) {
        throw new InvalidConfException(
            "baseUrl must be present and not blank.");
      }

      if (caProfiles == null || caProfiles.isEmpty()) {
        throw new InvalidConfException(
            "profiles must be present and not empty.");
      }
    }

    public static Acme parse(JsonMap json) throws CodecException {
      Acme ret = new Acme();
      ret.setBaseUrl(json.getString("baseUrl"));
      ret.setCaaIdentities(json.getStringList("caaIdentities"));
      ret.setDbConf(json.getString("dbConf"));
      Integer i = json.getInt("cacheSize");
      if (i != null) {
        ret.setCacheSize(i);
      }

      i = json.getInt("nonceNumBytes");
      if (i != null) {
        ret.setNonceNumBytes(i);
      }

      i = json.getInt("tokenNumBytes");
      if (i != null) {
        ret.setTokenNumBytes(i);
      }

      i = json.getInt("syncDbSeconds");
      if (i != null) {
        ret.setSyncDbSeconds(i);
      }

      ret.setContactVerifier(json.getString("contactVerifier"));
      ret.setTermsOfService(json.getString("termsOfService"));
      ret.setWebsite(json.getString("website"));

      JsonMap map = json.getMap("cleanupOrder");
      if (map != null) {
        ret.setCleanupOrder(CleanupOrderConf.parse(map));
      }

      JsonList list = json.getList("caProfiles");
      if (list != null) {
        List<CaProfile> caProfiles = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          caProfiles.add(CaProfile.parse(v));
        }
        ret.setCaProfiles(caProfiles);
      }

      ret.setChallengeTypes(json.getStringList("challengeTypes"));
      return ret;
    }
  }

  public static class CleanupOrderConf {

    private final int expiredCertDays;

    private final int expiredOrderDays;

    public CleanupOrderConf(int expiredCertDays, int expiredOrderDays) {
      this.expiredCertDays = expiredCertDays;
      this.expiredOrderDays = expiredOrderDays;
    }

    public int getExpiredCertDays() {
      return expiredCertDays;
    }

    public int getExpiredOrderDays() {
      return expiredOrderDays;
    }

    public static CleanupOrderConf parse(JsonMap json) throws CodecException {
      return new CleanupOrderConf(json.getNnInt("expiredCertDays"),
          json.getNnInt("expiredOrderDays"));
    }

  }

}
