// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import java.nio.charset.StandardCharsets;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.*;
import org.xipki.mgmt.web.core.*;
import org.xipki.util.misc.PemEncoder;
import org.xipki.util.misc.PemEncoder.PemLabel;

/**
 * Certificate response DTO.
 *
 * @author palos
 */
public class CertDto {

  public String serialNumber;
  public String subject;
  public String issuer;
  public String notBefore;
  public String notAfter;
  public String certPem;
  public String profile;
  // revocation
  public Boolean revoked;
  public String revocationTime;
  public String revocationReason;
  public String invalidityTime;

  public static CertDto fromCertWithRevocation(CertWithRevocationInfo info) {
    CertDto dto = new CertDto();
    X509Cert cert = info.getCert().getCert();
    dto.subject = cert.getSubjectText();
    dto.issuer = cert.getIssuerText();
    dto.serialNumber = cert.getSerialNumber().toString(16);
    dto.notBefore = cert.getNotBefore().toString();
    dto.notAfter = cert.getNotAfter().toString();
    dto.profile = info.getCertprofile();

    try {
      dto.certPem =
          new String(
              PemEncoder.encode(cert.getEncoded(), PemLabel.CERTIFICATE),
              StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new IllegalStateException("Unable to encode the certificate", e);
    }

    dto.setRevocation(info.getRevInfo());

    return dto;
  }

  public static CertDto fromCertListInfo(CertListInfo info) {
    CertDto dto = new CertDto();
    dto.serialNumber = info.getSerialNumber().toString(16);
    dto.subject = info.getSubject().toString();
    dto.notBefore = info.getNotBefore().toString();
    dto.notAfter = info.getNotAfter().toString();
    dto.revoked = false;
    dto.setRevocation(info.getRevocationInfo());
    return dto;
  }

  private void setRevocation(CertRevocationInfo rev) {
    if (rev == null) {
      return;
    }
    revoked = true;
    revocationTime = rev.getRevocationTime() == null ? null : rev.getRevocationTime().toString();
    revocationReason = rev.getReason() == null ? null : rev.getReason().getDescription();
    invalidityTime = rev.getInvalidityTime() == null ? null : rev.getInvalidityTime().toString();
  }

  // Getters and setters
  public String getSerialNumber() {
    return serialNumber;
  }

  public void setSerialNumber(String serialNumber) {
    this.serialNumber = serialNumber;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
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

  public String getCertPem() {
    return certPem;
  }

  public void setCertPem(String certPem) {
    this.certPem = certPem;
  }

  public String getProfile() {
    return profile;
  }

  public void setProfile(String profile) {
    this.profile = profile;
  }

  public Boolean isRevoked() {
    return revoked;
  }

  public void setRevoked(Boolean revoked) {
    this.revoked = revoked;
  }

  public String getRevocationTime() {
    return revocationTime;
  }

  public void setRevocationTime(String revocationTime) {
    this.revocationTime = revocationTime;
  }

  public String getRevocationReason() {
    return revocationReason;
  }

  public void setRevocationReason(String revocationReason) {
    this.revocationReason = revocationReason;
  }

  public String getInvalidityTime() {
    return invalidityTime;
  }

  public void setInvalidityTime(String invalidityTime) {
    this.invalidityTime = invalidityTime;
  }
}
