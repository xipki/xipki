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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.client.api.CertprofileInfo;
import org.xipki.security.util.X509Util;
import org.xipki.util.ParamUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class ClientCaConf {

  private final String name;

  private final String url;

  private final String healthUrl;

  private final String requestorName;

  private final ClientCmpResponder responder;

  private ClientCmpAgent agent;

  private boolean certAutoconf;

  private boolean certprofilesAutoconf;

  private boolean cmpControlAutoconf;

  private X509Certificate cert;

  private X500Name subject;

  private byte[] subjectKeyIdentifier;

  private ClientCmpControl cmpControl;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private Map<String, CertprofileInfo> profiles = Collections.emptyMap();

  ClientCaConf(String name, String url, String healthUrl, String requestorName,
      ClientCmpResponder responder,
      SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.name = ParamUtil.requireNonBlankLower("name", name);
    this.url = ParamUtil.requireNonBlank("url", url);
    this.requestorName = ParamUtil.requireNonNull("requestorName", requestorName);
    this.responder = ParamUtil.requireNonNull("responder", responder);
    this.healthUrl = StringUtil.isBlank(healthUrl) ? url.replace("cmp", "health") : healthUrl;
    this.sslSocketFactory = sslSocketFactory;
    this.hostnameVerifier = hostnameVerifier;
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

  public void setCertprofiles(Set<CertprofileInfo> certprofiles) {
    if (profiles == null) {
      this.profiles = Collections.emptyMap();
    } else {
      this.profiles = new HashMap<>();
      for (CertprofileInfo m : certprofiles) {
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
    return profiles.containsKey(ParamUtil.requireNonBlankLower("profileName", profileName));
  }

  public CertprofileInfo getProfile(String profileName) {
    return profiles.get(ParamUtil.requireNonBlankLower("profileName", profileName));
  }

  public boolean isCaInfoConfigured() {
    return cert != null;
  }

  public ClientCmpResponder getResponder() {
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

  public void setAgent(ClientCmpAgent agent) {
    this.agent = agent;
  }

  public String getRequestorName() {
    return requestorName;
  }

  public ClientCmpAgent getAgent() {
    return agent;
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

  public SSLSocketFactory getSslSocketFactory() {
    return sslSocketFactory;
  }

  public void setSslSocketFactory(SSLSocketFactory sslSocketFactory) {
    this.sslSocketFactory = sslSocketFactory;
  }

  public HostnameVerifier getHostnameVerifier() {
    return hostnameVerifier;
  }

  public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
    this.hostnameVerifier = hostnameVerifier;
  }

}
