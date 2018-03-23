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

package org.xipki.ca.client.impl;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.api.CertprofileInfo;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaConf {

  private final String name;

  private final String url;

  private final String healthUrl;

  private final String requestorName;

  private final CmpResponder responder;

  private X509CmpRequestor requestor;

  private boolean certAutoconf;

  private boolean certprofilesAutoconf;

  private boolean cmpControlAutoconf;

  private X509Certificate cert;

  private X500Name subject;

  private byte[] subjectKeyIdentifier;

  private ClientCmpControl cmpControl;

  private Map<String, CertprofileInfo> profiles = Collections.emptyMap();

  CaConf(String name, String url, String healthUrl, String requestorName, CmpResponder responder) {
    this.name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    this.url = ParamUtil.requireNonBlank("url", url);
    this.requestorName = ParamUtil.requireNonNull("requestorName", requestorName);
    this.responder = ParamUtil.requireNonNull("responder", responder);
    this.healthUrl = StringUtil.isBlank(healthUrl) ? url.replace("cmp", "health") : healthUrl;
  }

  public String getName() {
    return name;
  }

  public String getUrl() {
    return url;
  }

  public String getHealthUrl() {
    return healthUrl;
  }

  public void setCert(X509Certificate cert) throws CertificateEncodingException {
    this.cert = cert;
    this.subject = (cert == null) ? null
        : X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    this.subjectKeyIdentifier = X509Util.extractSki(cert);
  }

  public void setCertprofiles(Set<CertprofileInfo> certProfiles) {
    if (profiles == null) {
      this.profiles = Collections.emptyMap();
    } else {
      this.profiles = new HashMap<>();
      for (CertprofileInfo m : certProfiles) {
        this.profiles.put(m.getName(), m);
      }
    }
  }

  public X509Certificate getCert() {
    return cert;
  }

  public X500Name getSubject() {
    return subject;
  }

  public Set<String> getProfileNames() {
    return profiles.keySet();
  }

  public boolean supportsProfile(String profileName) {
    ParamUtil.requireNonNull("profileName", profileName);
    return profiles.containsKey(profileName.toLowerCase());
  }

  public CertprofileInfo getProfile(String profileName) {
    ParamUtil.requireNonNull("profileName", profileName);
    return profiles.get(profileName.toLowerCase());
  }

  public boolean isCaInfoConfigured() {
    return cert != null;
  }

  public CmpResponder getResponder() {
    return responder;
  }

  public boolean isCertAutoconf() {
    return certAutoconf;
  }

  public void setCertAutoconf(boolean autoconf) {
    this.certAutoconf = autoconf;
  }

  public boolean isCertprofilesAutoconf() {
    return certprofilesAutoconf;
  }

  public void setCertprofilesAutoconf(boolean autoconf) {
    this.certprofilesAutoconf = autoconf;
  }

  public void setRequestor(X509CmpRequestor requestor) {
    this.requestor = requestor;
  }

  public String getRequestorName() {
    return requestorName;
  }

  public X509CmpRequestor getRequestor() {
    return requestor;
  }

  public void setCmpControlAutoconf(boolean autoconf) {
    this.cmpControlAutoconf = autoconf;
  }

  public boolean isCmpControlAutoconf() {
    return cmpControlAutoconf;
  }

  public void setCmpControl(ClientCmpControl cmpControl) {
    this.cmpControl = cmpControl;
  }

  public ClientCmpControl getCmpControl() {
    return cmpControl;
  }

  public byte[] getSubjectKeyIdentifier() {
    return (subjectKeyIdentifier == null) ? null
        : Arrays.copyOf(subjectKeyIdentifier, subjectKeyIdentifier.length);
  }

}
