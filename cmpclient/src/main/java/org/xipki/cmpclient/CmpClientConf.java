/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.cmpclient;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xipki.util.FileOrBinary;
import org.xipki.util.FileOrValue;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */

public class CmpClientConf extends ValidatableConf {

  public static class Ca extends ValidatableConf {

    private String name;

    private String url;

    private String healthUrl;

    private String ssl;

    private String requestor;

    private String responder;

    private Cmpcontrol cmpcontrol;

    private Certs caCertchain;

    private Certs dhpocCerts;

    private Certprofiles certprofiles;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getHealthUrl() {
      return healthUrl;
    }

    public void setHealthUrl(String healthUrl) {
      this.healthUrl = healthUrl;
    }

    public String getSsl() {
      return ssl;
    }

    public void setSsl(String ssl) {
      this.ssl = ssl;
    }

    public String getRequestor() {
      return requestor;
    }

    public void setRequestor(String requestor) {
      this.requestor = requestor;
    }

    public String getResponder() {
      return responder;
    }

    public void setResponder(String responder) {
      this.responder = responder;
    }

    public Cmpcontrol getCmpcontrol() {
      return cmpcontrol;
    }

    public void setCmpcontrol(Cmpcontrol cmpcontrol) {
      this.cmpcontrol = cmpcontrol;
    }

    public Certs getCaCertchain() {
      return caCertchain;
    }

    public void setCaCertchain(Certs caCertchain) {
      this.caCertchain = caCertchain;
    }

    public Certs getDhpocCerts() {
      return dhpocCerts;
    }

    public void setDhpocCerts(Certs dhpocCerts) {
      this.dhpocCerts = dhpocCerts;
    }

    public Certprofiles getCertprofiles() {
      return certprofiles;
    }

    public void setCertprofiles(Certprofiles certprofiles) {
      this.certprofiles = certprofiles;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      notEmpty(url, "url");
      notEmpty(requestor, "requestor");
      notEmpty(responder, "responder");
      validate(cmpcontrol);
      validate(caCertchain);
      validate(certprofiles);
      validate(dhpocCerts);
    }

  }

  public static class Certs extends ValidatableConf {

    private boolean autoconf;

    private List<FileOrBinary> certificates;

    public boolean isAutoconf() {
      return autoconf;
    }

    public void setAutoconf(boolean autoconf) {
      this.autoconf = autoconf;
    }

    public List<FileOrBinary> getCertificates() {
      return autoconf ? null : certificates;
    }

    public void setCertificates(List<FileOrBinary> certificates) {
      this.certificates = certificates;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (!autoconf) {
        notEmpty(certificates, "certificates");
        for (FileOrBinary m : certificates) {
          m.validate();
        }
      }
    }

  }

  public static class Certprofile extends ValidatableConf {

    private String name;

    private String type;

    private FileOrValue conf;

    public String getName() {
      return name;
    }

    public void setName(String value) {
      this.name = value;
    }

    public String getType() {
      return type;
    }

    public void setType(String value) {
      this.type = value;
    }

    public FileOrValue getConf() {
      return conf;
    }

    public void setConf(FileOrValue value) {
      this.conf = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      validate(conf);
    }

  }

  public static class Certprofiles extends ValidatableConf {

    private boolean autoconf;

    private List<Certprofile> profiles;

    public boolean isAutoconf() {
      return autoconf;
    }

    public void setAutoconf(boolean autoconf) {
      this.autoconf = autoconf;
    }

    public List<Certprofile> getProfiles() {
      if (autoconf) {
        return Collections.emptyList();
      } else {
        if (profiles == null) {
          profiles = new LinkedList<>();
        }
        return profiles;
      }
    }

    public void setProfiles(List<Certprofile> profiles) {
      this.profiles = profiles;
    }

    @Override
    public void validate() throws InvalidConfException {
      if (!autoconf) {
        validate(profiles);
      }
    }

  }

  public static class Cmpcontrol extends ValidatableConf {

    private boolean autoconf;

    private Boolean rrAkiRequired;

    public boolean isAutoconf() {
      return autoconf;
    }

    public void setAutoconf(boolean autoconf) {
      this.autoconf = autoconf;
    }

    public Boolean getRrAkiRequired() {
      return autoconf ? null : rrAkiRequired;
    }

    public void setRrAkiRequired(Boolean rrAkiRequired) {
      this.rrAkiRequired = rrAkiRequired;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  }

  public static class Requestor extends ValidatableConf {

    private String name;

    private boolean signRequest;

    private Requestor.PbmMac pbmMac;

    private Requestor.Signature signature;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public boolean isSignRequest() {
      return signRequest;
    }

    public void setSignRequest(boolean signRequest) {
      this.signRequest = signRequest;
    }

    public Requestor.PbmMac getPbmMac() {
      return pbmMac;
    }

    public void setPbmMac(Requestor.PbmMac pbmMac) {
      this.pbmMac = pbmMac;
    }

    public Requestor.Signature getSignature() {
      return signature;
    }

    public void setSignature(Requestor.Signature signature) {
      this.signature = signature;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      exactOne(pbmMac, "pbmMac", signature, "signature");
      validate(pbmMac);
      validate(signature);
    }

    public static class PbmMac extends ValidatableConf {

      private byte[] kid;

      private String sender;

      private String password;

      private String owf;

      private int iterationCount;

      private String mac;

      public byte[] getKid() {
        return kid;
      }

      public void setKid(byte[] kid) {
        this.kid = kid;
      }

      public String getSender() {
        return sender;
      }

      public void setSender(String sender) {
        this.sender = sender;
      }

      public String getPassword() {
        return password;
      }

      public void setPassword(String password) {
        this.password = password;
      }

      public String getOwf() {
        return owf;
      }

      public void setOwf(String owf) {
        this.owf = owf;
      }

      public int getIterationCount() {
        return iterationCount;
      }

      public void setIterationCount(int iterationCount) {
        this.iterationCount = iterationCount;
      }

      public String getMac() {
        return mac;
      }

      public void setMac(String mac) {
        this.mac = mac;
      }

      @Override
      public void validate() throws InvalidConfException {
        notNull(kid, "kid");
        notEmpty(sender, "sender");
        notEmpty(password, "password");
        notEmpty("owf", owf);
        notEmpty(mac, "mac");
      }

    }

    public static class Signature extends ValidatableConf {

      private FileOrBinary cert;

      private String signerType;

      private String signerConf;

      public FileOrBinary getCert() {
        return cert;
      }

      public void setCert(FileOrBinary cert) {
        this.cert = cert;
      }

      public String getSignerType() {
        return signerType;
      }

      public void setSignerType(String signerType) {
        this.signerType = signerType;
      }

      public String getSignerConf() {
        return signerConf;
      }

      public void setSignerConf(String signerConf) {
        this.signerConf = signerConf;
      }

      @Override
      public void validate() throws InvalidConfException {
        validate(cert);
      }

    }

  }

  public static class Responder extends ValidatableConf {

    private String name;

    private FileOrBinary cert;

    private Responder.PbmMac pbmMac;

    private Responder.Signature signature;

    public String getName() {
      return name;
    }

    public void setName(String value) {
      this.name = value;
    }

    public FileOrBinary getCert() {
      return cert;
    }

    public void setCert(FileOrBinary value) {
      this.cert = value;
    }

    public Responder.PbmMac getPbmMac() {
      return pbmMac;
    }

    public void setPbmMac(Responder.PbmMac value) {
      this.pbmMac = value;
    }

    public Responder.Signature getSignature() {
      return signature;
    }

    public void setSignature(Responder.Signature value) {
      this.signature = value;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
      validate(cert);
      exactOne(pbmMac, "pbmMac", signature, "signature");
      validate(pbmMac);
      validate(signature);
    }

    public static class PbmMac extends ValidatableConf {

      private List<String> owfAlgos;

      private List<String> macAlgos;

      public List<String> getOwfAlgos() {
        if (owfAlgos == null) {
          owfAlgos = new LinkedList<>();
        }
        return owfAlgos;
      }

      public void setOwfAlgos(List<String> owfAlgos) {
        this.owfAlgos = owfAlgos;
      }

      public List<String> getMacAlgos() {
        if (macAlgos == null) {
          macAlgos = new LinkedList<>();
        }
        return macAlgos;
      }

      public void setMacAlgos(List<String> macAlgos) {
        this.macAlgos = macAlgos;
      }

      @Override
      public void validate() throws InvalidConfException {
        notEmpty(owfAlgos, "owfAlgos");
        notEmpty(macAlgos, "macAlgos");
      }

    }

    public static class Signature extends ValidatableConf {

      private List<String> signatureAlgos;

      public List<String> getSignatureAlgos() {
        if (signatureAlgos == null) {
          signatureAlgos = new LinkedList<>();
        }
        return signatureAlgos;
      }

      public void setSignatureAlgos(List<String> signatureAlgos) {
        this.signatureAlgos = signatureAlgos;
      }

      @Override
      public void validate() throws InvalidConfException {
        notEmpty(signatureAlgos, "signatureAlgos");
      }

    }

  }

  public static class Ssl extends ValidatableConf {

    private String name;

    private String storeType;

    private FileOrBinary keystore;

    private String keystorePassword;

    private FileOrBinary truststore;

    private String truststorePassword;

    /**
     * Valid values are {@code null}, no_op, default, or java:{qualified class name}
     * (without the brackets).
     */
    private String hostnameVerifier;

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getStoreType() {
      return storeType;
    }

    public void setStoreType(String storeType) {
      this.storeType = storeType;
    }

    public FileOrBinary getKeystore() {
      return keystore;
    }

    public void setKeystore(FileOrBinary keystore) {
      this.keystore = keystore;
    }

    public String getKeystorePassword() {
      return keystorePassword;
    }

    public void setKeystorePassword(String keystorePassword) {
      this.keystorePassword = keystorePassword;
    }

    public FileOrBinary getTruststore() {
      return truststore;
    }

    public void setTruststore(FileOrBinary truststore) {
      this.truststore = truststore;
    }

    public String getTruststorePassword() {
      return truststorePassword;
    }

    public void setTruststorePassword(String truststorePassword) {
      this.truststorePassword = truststorePassword;
    }

    public String getHostnameVerifier() {
      return hostnameVerifier;
    }

    public void setHostnameVerifier(String hostnameVerifier) {
      this.hostnameVerifier = hostnameVerifier;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(name, "name");
    }

  }

  private List<Ssl> ssls;

  private List<Requestor> requestors;

  private List<Responder> responders;

  /**
   * Interval in minutes to update the CA information if autoconf is activated.
   * Default to be 10, value between 1 and 4 will be converted to 5, value less than 1
   * disables the interval update.
   */
  private Integer cainfoUpdateInterval;

  private List<Ca> cas;

  public List<Ssl> getSsls() {
    if (ssls == null) {
      ssls = new LinkedList<>();
    }
    return ssls;
  }

  public void setSsls(List<Ssl> ssls) {
    this.ssls = ssls;
  }

  public List<Requestor> getRequestors() {
    if (requestors == null) {
      requestors = new LinkedList<>();
    }
    return requestors;
  }

  public void setRequestors(List<Requestor> requestors) {
    this.requestors = requestors;
  }

  public List<Responder> getResponders() {
    if (responders == null) {
      responders = new LinkedList<>();
    }
    return responders;
  }

  public void setResponders(List<Responder> responders) {
    this.responders = responders;
  }

  public Integer getCainfoUpdateInterval() {
    return cainfoUpdateInterval;
  }

  public void setCainfoUpdateInterval(Integer cainfoUpdateInterval) {
    this.cainfoUpdateInterval = cainfoUpdateInterval;
  }

  public List<Ca> getCas() {
    if (cas == null) {
      cas = new LinkedList<>();
    }
    return cas;
  }

  public void setCas(List<Ca> cas) {
    this.cas = cas;
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(ssls);
    notEmpty(requestors, "requestors");
    validate(requestors);
    notEmpty(responders, "responders");
    validate(responders);
    notEmpty(cas, "cas");
    validate(cas);
  }

}
