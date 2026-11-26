// License Apache License 2.0

package org.xipki.mgmt.web.dto;

import org.xipki.mgmt.web.core.*;

/**
 * Deliberately has no generated toString: the password must never be logged.
 *
 * @author palos
 */
public class KeyCertDownloadRequest extends StrictRequest {
  public String ca;
  public String profile;
  public String subject;
  public String notBefore;
  public String notAfter;
  public String downloadPassword;

  public String getCa() {
    return ca;
  }

  public void setCa(String value) {
    ca = value;
  }

  public String getProfile() {
    return profile;
  }

  public void setProfile(String value) {
    profile = value;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String value) {
    subject = value;
  }

  public String getNotBefore() {
    return notBefore;
  }

  public void setNotBefore(String value) {
    notBefore = value;
  }

  public String getNotAfter() {
    return notAfter;
  }

  public void setNotAfter(String value) {
    notAfter = value;
  }

  public String getDownloadPassword() {
    return downloadPassword;
  }

  public void setDownloadPassword(String value) {
    downloadPassword = value;
  }
}
