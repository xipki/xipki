// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.math.BigInteger;
import java.time.Instant;
import java.util.*;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.Crypto.X509Cert;
import org.xipki.util.conf.Validity;

/**
 * Console's stable management data model. Official XiPKI types are isolated in
 * OfficialCaMgmtClientAdapter so controllers do not depend on transport details.
 *
 * @author palos
 */
public final class CaDomain {
  private CaDomain() {}

  public static class CaMgmtException extends Exception {
    public CaMgmtException(String message) {
      super(message);
    }

    public CaMgmtException(Throwable cause) {
      super(cause);
    }

    public CaMgmtException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public record NameId(Integer id, String name) {
    public Integer getId() {
      return id;
    }

    public String getName() {
      return name;
    }
  }

  public enum CaStatus {
    active,
    inactive;

    public static CaStatus forName(String name) {
      return valueOf(name.toLowerCase(Locale.ROOT));
    }
  }

  public enum ValidityMode {
    STRICT,
    CUTOFF,
    BY_CA;

    public static ValidityMode forName(String name) {
      return valueOf(
          name.equalsIgnoreCase("LAX")
                  || name.equalsIgnoreCase("BY-CA")
                  || name.equalsIgnoreCase("BYCA")
              ? "BY_CA"
              : name.toUpperCase(Locale.ROOT));
    }
  }

  public enum CaSystemStatus {
    STARTED_AS_MASTER,
    STARTED_AS_SLAVE,
    NOT_INITED,
    INITIALIZING,
    LOCK_FAILED,
    ERROR
  }

  public enum CertListOrderBy {
    NOT_BEFORE("notBefore"),
    NOT_BEFORE_DESC("notBefore-desc"),
    NOT_AFTER("notAfter"),
    NOT_AFTER_DESC("notAfter-desc"),
    SUBJECT("subject"),
    SUBJECT_DESC("subject-desc");
    private final String text;

    CertListOrderBy(String text) {
      this.text = text;
    }

    public String getText() {
      return text;
    }

    public static CertListOrderBy forValue(String value) {
      for (var v : values()) {
        if (v.text.equalsIgnoreCase(value) || v.name().equalsIgnoreCase(value)) {
          return v;
        }
      }
      return null;
    }
  }

  public static final class PermissionConstants {
    public static final int ENROLL_CERT = 1,
        REVOKE_CERT = 2,
        UNSUSPEND_CERT = 4,
        REMOVE_CERT = 8,
        REENROLL_CERT = 16,
        GEN_CRL = 32,
        GET_CRL = 64,
        ENROLL_CROSS = 128,
        GEN_KEYPAIR = 256,
        GET_CERT = 512,
        ALL = 1023;
    private static final List<String> NAMES =
        List.of(
            "enroll_cert",
            "revoke_cert",
            "unsuspend_cert",
            "remove_cert",
            "reenroll_cert",
            "gen_crl",
            "get_crl",
            "enroll_cross",
            "gen_keypair",
            "get_cert");
  }

  public static class Permissions {
    private final int value;

    public Permissions(int value) {
      this.value = value;
    }

    public Permissions(Collection<String> names) {
      int bits = 0;
      for (String n : names) {
        if ("all".equalsIgnoreCase(n)) {
          bits = 1023;
          break;
        }
        if ("none".equalsIgnoreCase(n)) {
          continue;
        }
        int i = PermissionConstants.NAMES.indexOf(n.toLowerCase(Locale.ROOT));
        if (i >= 0) {
          bits |= 1 << i;
        } else {
          try {
            bits |= Integer.parseInt(n);
          } catch (Exception e) {
            throw new IllegalArgumentException("Unknown permission");
          }
        }
      }
      this.value = bits;
    }

    public int getValue() {
      return value;
    }

    public boolean isPermitted(int bit) {
      return (value & bit) == bit;
    }

    public List<String> toPermissionTexts() {
      if (value == 1023) {
        return List.of("all");
      }
      var a = new ArrayList<String>();
      for (int i = 0; i < 10; i++) {
        if ((value & (1 << i)) != 0) {
          a.add(PermissionConstants.NAMES.get(i));
        }
      }
      return a;
    }
  }

  public enum CrlReason {
    UNSPECIFIED(0, "unspecified"),
    KEY_COMPROMISE(1, "keyCompromise"),
    CA_COMPROMISE(2, "cACompromise"),
    AFFILIATION_CHANGED(3, "affiliationChanged"),
    SUPERSEDED(4, "superseded"),
    CESSATION_OF_OPERATION(5, "cessationOfOperation"),
    CERTIFICATE_HOLD(6, "certificateHold"),
    REMOVE_FROM_CRL(8, "removeFromCRL"),
    PRIVILEGE_WITHDRAWN(9, "privilegeWithdrawn"),
    AA_COMPROMISE(10, "aACompromise");
    private final int code;
    private final String description;

    CrlReason(int c, String d) {
      code = c;
      description = d;
    }

    public int getCode() {
      return code;
    }

    public String getDescription() {
      return description;
    }

    public static CrlReason forNameOrText(String text) {
      for (var r : values()) {
        if (r.name().equalsIgnoreCase(text)
            || r.description.equalsIgnoreCase(text)
            || Integer.toString(r.code).equals(text)) {
          return r;
        }
      }
      throw new IllegalArgumentException("Unknown revocation reason");
    }
  }

  public record CertRevocationInfo(
      CrlReason reason, Instant revocationTime, Instant invalidityTime) {
    public CrlReason getReason() {
      return reason;
    }

    public Instant getRevocationTime() {
      return revocationTime;
    }

    public Instant getInvalidityTime() {
      return invalidityTime;
    }
  }

  public record CaUris(
      List<String> cacertUris,
      List<String> ocspUris,
      List<String> crlUris,
      List<String> deltaCrlUris) {
    public List<String> getCacertUris() {
      return cacertUris;
    }

    public List<String> getOcspUris() {
      return ocspUris;
    }

    public List<String> getCrlUris() {
      return crlUris;
    }

    public List<String> getDeltaCrlUris() {
      return deltaCrlUris;
    }
  }

  private static boolean flag(ConfPairs pairs, String key, boolean fallback) {
    String value = pairs.value(key);
    if (value == null) {
      return fallback;
    }
    if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
      throw new IllegalArgumentException("Invalid boolean control: " + key);
    }
    return Boolean.parseBoolean(value);
  }

  private static int number(ConfPairs pairs, String key, int fallback) {
    String value = pairs.value(key);
    return value == null ? fallback : Integer.parseInt(value);
  }

  public static class CrlControl {
    private final String conf;

    public CrlControl(String conf) {
      var p = new ConfPairs(conf);
      int hours = number(p, "interval.hours", 24);
      if (!Set.of(1, 2, 3, 4, 6, 8, 12, 24).contains(hours)) {
        throw new IllegalArgumentException("Invalid CRL interval hours");
      }
      int full = number(p, "fullcrl.intervals", 168 / hours),
          delta = number(p, "deltacrl.intervals", 0);
      long fullHours = (long) full * hours, deltaHours = (long) delta * hours;
      if (full < 1
          || delta < 0
          || (delta > 0 && delta >= full)
          || !(fullHours % 24 == 0 || 24 % fullHours == 0)
          || (delta > 0 && !(deltaHours % 24 == 0 || 24 % deltaHours == 0))) {
        throw new IllegalArgumentException("Invalid full/delta CRL intervals");
      }
      String time = Objects.requireNonNullElse(p.value("interval.time"), "01:00");
      if (!time.matches("[0-9]{1,2}:[0-9]{1,2}")) {
        throw new IllegalArgumentException("Invalid CRL time");
      }
      String[] parts = time.split(":");
      int hour = Integer.parseInt(parts[0]), minute = Integer.parseInt(parts[1]);
      if (hour > 23 || minute > 59) {
        throw new IllegalArgumentException("Invalid CRL time");
      }
      String mode = Objects.requireNonNullElse(p.value("invalidity.date"), "optional");
      if (!Set.of("required", "optional", "forbidden").contains(mode)) {
        throw new IllegalArgumentException("Invalid invalidity-date mode");
      }
      String overlap =
          p.value("overlap.days") != null
              ? number(p, "overlap.days", 1) + "d"
              : p.value("overlap.minutes") != null
                  ? number(p, "overlap.minutes", 1440) + "m"
                  : Objects.requireNonNullElse(p.value("overlap"), "1d");
      var validity = Validity.getInstance(overlap);
      if (validity.validity() < 1) {
        validity = Validity.getInstance("3d");
      }
      this.conf =
          new ConfPairs()
              .putPair("interval.hours", Integer.toString(hours))
              .putPair("fullcrl.intervals", Integer.toString(full))
              .putPair("deltacrl.intervals", Integer.toString(delta))
              .putPair(
                  "interval.time", String.format(Locale.ROOT, "%02d:%02d", hour % hours, minute))
              .putPair("invalidity.date", mode)
              .putPair("overlap", validity.toString())
              .putPair("exclude.reason", Boolean.toString(flag(p, "exclude.reason", false)))
              .putPair(
                  "include.expiredcerts", Boolean.toString(flag(p, "include.expiredcerts", false)))
              .putPair(
                  "fullcrl.extended.nextupdate",
                  Boolean.toString(flag(p, "fullcrl.extended.nextupdate", false)))
              .getEncoded();
    }

    public String getConf() {
      return conf;
    }
  }

  public static class CtlogControl {
    private final String conf;

    public CtlogControl(String conf) {
      var p = new ConfPairs(conf);
      boolean enabled = flag(p, "enabled", false);
      if (p.value("servers") == null || p.value("servers").isBlank()) {
        throw new IllegalArgumentException("CT servers required");
      }
      p.putPair("enabled", Boolean.toString(enabled));
      this.conf = p.getEncoded();
    }

    public String getConf() {
      return conf;
    }
  }

  public static class RevokeSuspendedControl {
    private final String conf;

    public RevokeSuspendedControl(String conf) {
      var p = new ConfPairs(conf);
      boolean enabled = flag(p, "enabled", false);
      var reason =
          CrlReason.forNameOrText(
              Objects.requireNonNullElse(p.value("targetReason"), "cessationOfOperation"));
      var age = Validity.getInstance(Objects.requireNonNullElse(p.value("unchangedSince"), "15d"));
      this.conf =
          new ConfPairs()
              .putPair("enabled", Boolean.toString(enabled))
              .putPair("targetReason", reason.getDescription())
              .putPair("unchangedSince", age.toString())
              .getEncoded();
    }

    public String getConf() {
      return conf;
    }
  }

  public static class BaseCaInfo {

    private String signerType;
    private CaUris caUris;
    private CrlControl crlControl;
    private String crlSignerName;
    private CtlogControl ctlogControl;
    private int expirationPeriod = 365;
    private ConfPairs extraControl;
    private int keepExpiredCertDays = -1;
    private List<String> keypairGenNames;
    private Validity maxValidity;
    private long nextCrlNo;
    private int numCrls = 30;
    private Permissions permissions;
    private CertRevocationInfo revocationInfo;
    private RevokeSuspendedControl revokeSuspendedControl;
    private boolean saveCert = true;
    private boolean saveKeypair = false;
    private int snSize = 20;
    private CaStatus status = CaStatus.active;
    private ValidityMode validityMode = ValidityMode.STRICT;

    public BaseCaInfo(String signerType, Permissions permissions) {
      this.signerType = signerType;
      this.permissions = permissions;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String value) {
      signerType = value;
    }

    public CaUris getCaUris() {
      return caUris;
    }

    public void setCaUris(CaUris value) {
      caUris = value;
    }

    public CrlControl getCrlControl() {
      return crlControl;
    }

    public void setCrlControl(CrlControl value) {
      crlControl = value;
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String value) {
      crlSignerName = value;
    }

    public CtlogControl getCtlogControl() {
      return ctlogControl;
    }

    public void setCtlogControl(CtlogControl value) {
      ctlogControl = value;
    }

    public int getExpirationPeriod() {
      return expirationPeriod;
    }

    public void setExpirationPeriod(int value) {
      expirationPeriod = value;
    }

    public ConfPairs getExtraControl() {
      return extraControl;
    }

    public void setExtraControl(ConfPairs value) {
      extraControl = value;
    }

    public int getKeepExpiredCertDays() {
      return keepExpiredCertDays;
    }

    public void setKeepExpiredCertDays(int value) {
      keepExpiredCertDays = value;
    }

    public List<String> getKeypairGenNames() {
      return keypairGenNames;
    }

    public void setKeypairGenNames(List<String> value) {
      keypairGenNames = value;
    }

    public Validity getMaxValidity() {
      return maxValidity;
    }

    public void setMaxValidity(Validity value) {
      maxValidity = value;
    }

    public long getNextCrlNo() {
      return nextCrlNo;
    }

    public void setNextCrlNo(long value) {
      nextCrlNo = value;
    }

    public int getNumCrls() {
      return numCrls;
    }

    public void setNumCrls(int value) {
      numCrls = value;
    }

    public Permissions getPermissions() {
      return permissions;
    }

    public void setPermissions(Permissions value) {
      permissions = value;
    }

    public CertRevocationInfo getRevocationInfo() {
      return revocationInfo;
    }

    public void setRevocationInfo(CertRevocationInfo value) {
      revocationInfo = value;
    }

    public RevokeSuspendedControl getRevokeSuspendedControl() {
      return revokeSuspendedControl;
    }

    public void setRevokeSuspendedControl(RevokeSuspendedControl value) {
      revokeSuspendedControl = value;
    }

    public boolean isSaveCert() {
      return saveCert;
    }

    public void setSaveCert(boolean value) {
      saveCert = value;
    }

    public boolean isSaveKeypair() {
      return saveKeypair;
    }

    public void setSaveKeypair(boolean value) {
      saveKeypair = value;
    }

    public int getSnSize() {
      return snSize;
    }

    public void setSnSize(int value) {
      if (value < 1 || value > 20) {
        throw new IllegalArgumentException("Invalid serial length");
      }
      snSize = value;
    }

    public CaStatus getStatus() {
      return status;
    }

    public void setStatus(CaStatus value) {
      status = value;
    }

    public ValidityMode getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(ValidityMode value) {
      validityMode = value;
    }
  }

  public static class ChangeCaEntry {

    private NameId ident;
    private CaStatus status;
    private Validity maxValidity;
    private ValidityMode validityMode;
    private List<String> permissions;
    private Integer serialNoLen;
    private Integer numCrls;
    private Integer expirationPeriod;
    private Integer keepExpiredCertDays;
    private Boolean saveCert;
    private Boolean saveKeypair;
    private List<String> keypairGenNames;
    private String crlSignerName;
    private String crlControl;
    private String ctlogControl;
    private String revokeSuspendedControl;
    private String extraControl;
    private CaUris caUris;
    private String signerType;
    private String signerConf;
    private byte[] encodedCert;
    private List<byte[]> encodedCertchain;

    public ChangeCaEntry(NameId ident) {
      this.ident = ident;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId value) {
      ident = value;
    }

    public CaStatus getStatus() {
      return status;
    }

    public void setStatus(CaStatus value) {
      status = value;
    }

    public Validity getMaxValidity() {
      return maxValidity;
    }

    public void setMaxValidity(Validity value) {
      maxValidity = value;
    }

    public ValidityMode getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(ValidityMode value) {
      validityMode = value;
    }

    public List<String> getPermissions() {
      return permissions;
    }

    public void setPermissions(List<String> value) {
      permissions = value;
    }

    public Integer getSerialNoLen() {
      return serialNoLen;
    }

    public void setSerialNoLen(Integer value) {
      if (value != null && (value < 1 || value > 20)) {
        throw new IllegalArgumentException("Invalid serial length");
      }
      serialNoLen = value;
    }

    public Integer getNumCrls() {
      return numCrls;
    }

    public void setNumCrls(Integer value) {
      numCrls = value;
    }

    public Integer getExpirationPeriod() {
      return expirationPeriod;
    }

    public void setExpirationPeriod(Integer value) {
      expirationPeriod = value;
    }

    public Integer getKeepExpiredCertDays() {
      return keepExpiredCertDays;
    }

    public void setKeepExpiredCertDays(Integer value) {
      keepExpiredCertDays = value;
    }

    public Boolean getSaveCert() {
      return saveCert;
    }

    public void setSaveCert(Boolean value) {
      saveCert = value;
    }

    public Boolean getSaveKeypair() {
      return saveKeypair;
    }

    public void setSaveKeypair(Boolean value) {
      saveKeypair = value;
    }

    public List<String> getKeypairGenNames() {
      return keypairGenNames;
    }

    public void setKeypairGenNames(List<String> value) {
      keypairGenNames = value;
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String value) {
      crlSignerName = value;
    }

    public String getCrlControl() {
      return crlControl;
    }

    public void setCrlControl(String value) {
      crlControl = value;
    }

    public String getCtlogControl() {
      return ctlogControl;
    }

    public void setCtlogControl(String value) {
      ctlogControl = value;
    }

    public String getRevokeSuspendedControl() {
      return revokeSuspendedControl;
    }

    public void setRevokeSuspendedControl(String value) {
      revokeSuspendedControl = value;
    }

    public String getExtraControl() {
      return extraControl;
    }

    public void setExtraControl(String value) {
      extraControl = value;
    }

    public CaUris getCaUris() {
      return caUris;
    }

    public void setCaUris(CaUris value) {
      caUris = value;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String value) {
      signerType = value;
    }

    public String getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(String value) {
      signerConf = value;
    }

    public byte[] getEncodedCert() {
      return encodedCert;
    }

    public void setEncodedCert(byte[] value) {
      encodedCert = value;
    }

    public List<byte[]> getEncodedCertchain() {
      return encodedCertchain;
    }

    public void setEncodedCertchain(List<byte[]> value) {
      encodedCertchain = value;
    }
  }

  public static class CaEntry {

    private BaseCaInfo base;
    private NameId ident;
    private String signerConf;
    private X509Cert cert;
    private List<X509Cert> certchain;

    public CaEntry(BaseCaInfo base, NameId ident, String signerConf) {
      this.base = base;
      this.ident = ident;
      this.signerConf = signerConf;
    }

    public BaseCaInfo getBase() {
      return base;
    }

    public void setBase(BaseCaInfo value) {
      base = value;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId value) {
      ident = value;
    }

    public String getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(String value) {
      signerConf = value;
    }

    public X509Cert getCert() {
      return cert;
    }

    public void setCert(X509Cert value) throws CaMgmtException {
      if (value != null) {
        boolean[] usage = value.getKeyUsage();
        if (value.getBasicConstraints() < 0 || usage == null || usage.length <= 5 || !usage[5]) {
          throw new CaMgmtException("CA certificate with keyCertSign required");
        }
      }
      cert = value;
    }

    public List<X509Cert> getCertchain() {
      return certchain;
    }

    public void setCertchain(List<X509Cert> value) {
      certchain = value;
    }
  }

  public static class CertprofileEntry {
    private transient boolean faulty;

    public boolean faulty() {
      return faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean value) {
      faulty = value;
    }

    private NameId ident;
    private String type;
    private String conf;

    public CertprofileEntry(NameId ident, String type, String conf) {
      this.ident = ident;
      this.type = type;
      this.conf = conf;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId value) {
      ident = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      type = value;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String value) {
      conf = value;
    }
  }

  public static class PublisherEntry {
    private transient boolean faulty;

    public boolean faulty() {
      return faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean value) {
      faulty = value;
    }

    private NameId ident;
    private String type;
    private String conf;

    public PublisherEntry(NameId ident, String type, String conf) {
      this.ident = ident;
      this.type = type;
      this.conf = conf;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId value) {
      ident = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      type = value;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String value) {
      conf = value;
    }
  }

  public static class RequestorEntry {
    private transient boolean faulty;

    public boolean faulty() {
      return faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean value) {
      faulty = value;
    }

    private NameId ident;
    private String type;
    private String conf;

    public RequestorEntry(NameId ident, String type, String conf) {
      this.ident = ident;
      this.type = type;
      this.conf = conf;
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId value) {
      ident = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      type = value;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String value) {
      conf = value;
    }
  }

  public static class KeypairGenEntry {
    private transient boolean faulty;

    public boolean faulty() {
      return faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean value) {
      faulty = value;
    }

    private String name;
    private String type;
    private String conf;

    public KeypairGenEntry(String name, String type, String conf) {
      this.name = name;
      this.type = type;
      this.conf = conf;
    }

    public String getName() {
      return name;
    }

    public void setName(String value) {
      name = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      type = value;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String value) {
      conf = value;
    }
  }

  public static class SignerEntry {
    private transient boolean faulty;

    public boolean faulty() {
      return faulty;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean value) {
      faulty = value;
    }

    private String name;
    private String type;
    private String conf;
    private String base64Cert;

    public SignerEntry(String name, String type, String conf, String base64Cert) {
      this.name = name;
      this.type = type;
      this.conf = conf;
      this.base64Cert = base64Cert;
    }

    public String getName() {
      return name;
    }

    public void setName(String value) {
      name = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      type = value;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String value) {
      conf = value;
    }

    public String base64Cert() {
      return base64Cert;
    }

    public String getBase64Cert() {
      return base64Cert;
    }

    public void setBase64Cert(String value) {
      base64Cert = value;
    }
  }

  public static class CaHasRequestorEntry {

    private NameId requestorIdent;
    private Permissions permissions;
    private Set<String> profiles;

    public CaHasRequestorEntry(NameId ident, Permissions permissions, Collection<String> profiles) {
      this.requestorIdent = ident;
      this.permissions = permissions;
      this.profiles = profiles == null ? null : new LinkedHashSet<>(profiles);
    }

    public NameId getRequestorIdent() {
      return requestorIdent;
    }

    public void setRequestorIdent(NameId value) {
      requestorIdent = value;
    }

    public Permissions getPermissions() {
      return permissions;
    }

    public void setPermissions(Permissions value) {
      permissions = value;
    }

    public Set<String> getProfiles() {
      return profiles;
    }

    public void setProfiles(Set<String> value) {
      profiles = value;
    }
  }

  public record CaProfileEntry(String profileName, Set<String> aliases) {
    public CaProfileEntry(String name, List<String> aliases) {
      this(name, aliases == null ? Set.of() : new LinkedHashSet<>(aliases));
    }

    public String getEncoded() {
      return profileName + (aliases.isEmpty() ? "" : ":" + String.join(",", aliases));
    }

    public String getProfileName() {
      return profileName;
    }

    public Set<String> getAliases() {
      return aliases;
    }

    public List<String> getProfileAliases() {
      return new ArrayList<>(aliases);
    }

    public boolean containsNameOrAlias(String name) {
      return profileName.equalsIgnoreCase(name)
          || aliases.stream().anyMatch(a -> a.equalsIgnoreCase(name));
    }

    public static CaProfileEntry decode(String text) {
      var parts = text.split(":", -1);
      return new CaProfileEntry(
          parts[0],
          parts.length < 2 || parts[1].isBlank()
              ? Set.of()
              : new LinkedHashSet<>(Arrays.asList(parts[1].split(","))));
    }
  }

  public record CertListInfo(
      BigInteger serialNumber,
      String subject,
      Instant notBefore,
      Instant notAfter,
      CertRevocationInfo revocationInfo) {
    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public String getSubject() {
      return subject;
    }

    public Instant getNotBefore() {
      return notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }

    public CertRevocationInfo getRevocationInfo() {
      return revocationInfo;
    }
  }

  public record CertWithDbId(X509Cert cert) {
    public X509Cert getCert() {
      return cert;
    }
  }

  public record CertWithRevocationInfo(
      CertWithDbId cert, String certprofile, CertRevocationInfo revInfo) {
    public CertWithDbId getCert() {
      return cert;
    }

    public String getCertprofile() {
      return certprofile;
    }

    public CertRevocationInfo getRevInfo() {
      return revInfo;
    }

    public boolean isRevoked() {
      return revInfo != null;
    }
  }

  public record KeyCertBytesPair(byte[] key, byte[] cert) {
    public byte[] getKey() {
      return key;
    }

    public byte[] getCert() {
      return cert;
    }
  }
}
