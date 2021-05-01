/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.cmpclient.internal;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.cmpclient.CertprofileInfo;
import org.xipki.security.X509Cert;
import org.xipki.util.StringUtil;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.CertificateEncodingException;
import java.util.*;

import static org.xipki.util.Args.*;

/**
 * Configuration of the remote CA.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class CaConf {

  static class CmpControl {

    private final boolean rrAkiRequired;

    public CmpControl(boolean rrAkiRequired) {
      this.rrAkiRequired = rrAkiRequired;
    }

    public boolean isRrAkiRequired() {
      return this.rrAkiRequired;
    }

  } // class CmpControl

  static class CaInfo {

    private final List<X509Cert> certchain;

    private final List<X509Cert> dhpocs;

    private final Set<CertprofileInfo> certprofiles;

    private final CmpControl cmpControl;

    CaInfo(List<X509Cert> certchain, CmpControl cmpControl,
        Set<CertprofileInfo> certprofiles, List<X509Cert> dhpocs) {
      this.certchain = certchain;
      this.cmpControl = cmpControl;
      this.certprofiles = certprofiles;
      this.dhpocs = dhpocs;
    }

    List<X509Cert> getCertchain() {
      return certchain;
    }

    List<X509Cert> getDhpocs() {
      return dhpocs;
    }

    CmpControl getCmpControl() {
      return cmpControl;
    }

    Set<CertprofileInfo> getCertprofiles() {
      return certprofiles;
    }

  } // class CaInfo

  private final String name;

  private final String url;

  private final String healthUrl;

  private final String requestorName;

  private final Responder responder;

  private CmpAgent agent;

  private boolean certAutoconf;

  private boolean certprofilesAutoconf;

  private boolean cmpControlAutoconf;

  private boolean dhpocAutoconf;

  private X509Cert cert;

  private List<X509Cert> certchain;

  private X500Name subject;

  private byte[] subjectKeyIdentifier;

  private CmpControl cmpControl;

  private SSLSocketFactory sslSocketFactory;

  private HostnameVerifier hostnameVerifier;

  private Map<String, CertprofileInfo> profiles = Collections.emptyMap();

  private List<X509Cert> dhpocs;

  CaConf(String name, String url, String healthUrl, String requestorName, Responder responder,
      SSLSocketFactory sslSocketFactory, HostnameVerifier hostnameVerifier) {
    this.name = toNonBlankLower(name, "name");
    this.url = notBlank(url, "url");
    this.requestorName = notNull(requestorName, "requestorName");
    this.responder = notNull(responder, "responder");
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

  public void setCertchain(List<X509Cert> certchain)
      throws CertificateEncodingException {
    notEmpty(certchain, "certchain");
    this.certchain = certchain;
    this.cert = certchain.get(0);
    this.subject = cert.getSubject();
    this.subjectKeyIdentifier = cert.getSubjectKeyId();
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

  public X509Cert getCert() {
    return cert;
  }

  public List<X509Cert> getCertchain() {
    return certchain;
  }

  public boolean isDhpocAutoconf() {
    return dhpocAutoconf;
  }

  public void setDhpocAutoconf(boolean dhpocAutoconf) {
    this.dhpocAutoconf = dhpocAutoconf;
  }

  public List<X509Cert> getDhpocs() {
    return dhpocs;
  }

  public void setDhpocs(List<X509Cert> dhpocs) {
    this.dhpocs = dhpocs;
  }

  public X500Name getSubject() {
    return subject;
  }

  public boolean isCertAutoconf() {
    return certAutoconf;
  }

  public Set<String> getProfileNames() {
    return profiles.keySet();
  }

  public boolean supportsProfile(String profileName) {
    return profiles.containsKey(toNonBlankLower(profileName, "profileName"));
  }

  public CertprofileInfo getProfile(String profileName) {
    return profiles.get(toNonBlankLower(profileName, "profileName"));
  }

  public boolean isCaInfoConfigured() {
    return cert != null;
  }

  public Responder getResponder() {
    return responder;
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

  public void setAgent(CmpAgent agent) {
    this.agent = agent;
  }

  public String getRequestorName() {
    return requestorName;
  }

  public CmpAgent getAgent() {
    return agent;
  }

  public void setCmpControlAutoconf(boolean autoconf) {
    this.cmpControlAutoconf = autoconf;
  }

  public boolean isCmpControlAutoconf() {
    return cmpControlAutoconf;
  }

  public void setCmpControl(CmpControl cmpControl) {
    this.cmpControl = cmpControl;
  }

  public CmpControl getCmpControl() {
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
