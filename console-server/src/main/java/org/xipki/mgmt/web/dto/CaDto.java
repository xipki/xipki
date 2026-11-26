// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.service.CaCertificateValidationService;
import org.xipki.util.misc.PemEncoder;
import org.xipki.util.misc.PemEncoder.PemLabel;

/**
 * CA response DTO.
 *
 * @author palos
 */
public class CaDto {

  public String name;
  public String status;
  public String subject;
  public String serialNumber;
  public String notBefore;
  public String notAfter;
  public String signerType;
  public String maxValidity;
  public String certPem;
  public int serialNoLen;
  public List<String> permissions;
  public List<String> aliases;
  public List<String> profiles;
  public List<String> publishers;
  public boolean saveCert;
  public boolean saveKeypair;
  public String runtimeState;
  public Map<String, String> revocationInfo;
  public String certificateFingerprint;
  public String issuer;
  public boolean selfSigned;
  public String revocationCheck;
  public String subjectKeyFingerprint;
  public int pathLength = -1;
  public String chainStatus;
  public List<String> chainCertificateFingerprints;
  public String parentCertificateFingerprint;
  public List<String> webPermissions;

  public static CaDto fromEntry(CaEntry entry) {
    CaDto dto = new CaDto();
    dto.name = entry.getIdent().getName();

    BaseCaInfo base = entry.getBase();
    if (base != null) {
      CaStatus caStatus = base.getStatus();
      dto.status = caStatus != null ? caStatus.name() : "unknown";
      dto.maxValidity = base.getMaxValidity() != null ? base.getMaxValidity().toString() : null;
      dto.serialNoLen = base.getSnSize();
      dto.saveCert = base.isSaveCert();
      dto.saveKeypair = base.isSaveKeypair();
      dto.signerType = base.getSignerType();
      var rev = base.getRevocationInfo();
      if (rev != null) {
        dto.revocationInfo = new LinkedHashMap<>();
        dto.revocationInfo.put("reason", rev.getReason().getDescription());
        dto.revocationInfo.put("revocationTime", rev.getRevocationTime().toString());
        if (rev.getInvalidityTime() != null) {
          dto.revocationInfo.put("invalidityTime", rev.getInvalidityTime().toString());
        }
      }
      if (base.getPermissions() != null) {
        dto.permissions = base.getPermissions().toPermissionTexts();
      }
    }

    X509Cert cert = entry.getCert();
    if (cert != null) {
      dto.subject = cert.getSubjectText();
      dto.issuer = cert.getIssuer() == null ? null : cert.getIssuer().toString();
      dto.selfSigned = CaCertificateValidationService.selfSigned(cert);
      dto.serialNumber = cert.getSerialNumber().toString(16);
      dto.notBefore = cert.getNotBefore().toString();
      dto.notAfter = cert.getNotAfter().toString();
      dto.certificateFingerprint = CaCertificateValidationService.fingerprint(cert);
      dto.subjectKeyFingerprint = CaCertificateValidationService.keyFingerprint(cert);
      dto.pathLength = cert.getBasicConstraints();
      dto.chainStatus = "unverified";
      dto.chainCertificateFingerprints = List.of(dto.certificateFingerprint);
      try {
        dto.certPem =
            new String(
                PemEncoder.encode(cert.getEncoded(), PemLabel.CERTIFICATE),
                StandardCharsets.UTF_8);
      } catch (Exception e) {
        throw new IllegalStateException("Unable to encode the CA certificate", e);
      }
    }

    return dto;
  }

  // Getters and setters
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(String serialNumber) {
    this.serialNumber = serialNumber;
  }

  public String getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(String notBefore) {
    this.notBefore = notBefore;
  }

  public String getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(String notAfter) {
    this.notAfter = notAfter;
  }

  public String getSignerType() {
    return signerType;
  }

  public void setSignerType(String signerType) {
    this.signerType = signerType;
  }

  public String getMaxValidity() {
    return maxValidity;
  }

  public void setMaxValidity(String maxValidity) {
    this.maxValidity = maxValidity;
  }

  public String getCertPem() {
    return certPem;
  }

  public void setCertPem(String certPem) {
    this.certPem = certPem;
  }

  public int getSerialNoLen() {
    return serialNoLen;
  }

  public void setSerialNoLen(int serialNoLen) {
    this.serialNoLen = serialNoLen;
  }

  public List<String> getPermissions() {
    return permissions;
  }

  public void setPermissions(List<String> permissions) {
    this.permissions = permissions;
  }

  public List<String> getAliases() {
    return aliases;
  }

  public void setAliases(List<String> aliases) {
    this.aliases = aliases;
  }

  public List<String> getProfiles() {
    return profiles;
  }

  public void setProfiles(List<String> profiles) {
    this.profiles = profiles;
  }

  public List<String> getPublishers() {
    return publishers;
  }

  public void setPublishers(List<String> publishers) {
    this.publishers = publishers;
  }

  public boolean isSaveCert() {
    return saveCert;
  }

  public void setSaveCert(boolean saveCert) {
    this.saveCert = saveCert;
  }

  public boolean isSaveKeypair() {
    return saveKeypair;
  }

  public void setSaveKeypair(boolean saveKeypair) {
    this.saveKeypair = saveKeypair;
  }

  public String getRuntimeState() {
    return runtimeState;
  }

  public void setRuntimeState(String state) {
    this.runtimeState = state;
  }

  public Map<String, String> getRevocationInfo() {
    return revocationInfo;
  }

  public void setRevocationInfo(Map<String, String> value) {
    this.revocationInfo = value;
  }

  public String getCertificateFingerprint() {
    return certificateFingerprint;
  }

  public void setCertificateFingerprint(String value) {
    certificateFingerprint = value;
  }

  public String getIssuer() {
    return issuer;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public void setSelfSigned(boolean value) {
    selfSigned = value;
  }

  public String getRevocationCheck() {
    return revocationCheck;
  }

  public void setRevocationCheck(String value) {
    revocationCheck = value;
  }

  public void setIssuer(String value) {
    issuer = value;
  }

  public String getSubjectKeyFingerprint() {
    return subjectKeyFingerprint;
  }

  public void setSubjectKeyFingerprint(String value) {
    subjectKeyFingerprint = value;
  }

  public int getPathLength() {
    return pathLength;
  }

  public void setPathLength(int value) {
    pathLength = value;
  }

  public String getChainStatus() {
    return chainStatus;
  }

  public void setChainStatus(String value) {
    chainStatus = value;
  }

  public List<String> getChainCertificateFingerprints() {
    return chainCertificateFingerprints;
  }

  public void setChainCertificateFingerprints(List<String> value) {
    chainCertificateFingerprints = value;
  }

  public String getParentCertificateFingerprint() {
    return parentCertificateFingerprint;
  }

  public void setParentCertificateFingerprint(String value) {
    parentCertificateFingerprint = value;
  }

  public List<String> getWebPermissions() {
    return webPermissions;
  }

  public void setWebPermissions(List<String> value) {
    webPermissions = value;
  }
}
