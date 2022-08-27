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

package org.xipki.scep.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.scep.client.CaCertValidator;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;
import org.xipki.util.StringUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

/**
 * Actions for CA client via SCEP.
 *
 * @author Lijun Liao
 */

public class Actions {

  @Command(scope = "xi", name = "scep-certpoll", description = "poll certificate")
  @Service
  public static class ScepCertpoll extends ClientAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertificationRequest csr = X509Util.parseCsr(new File(csrFile));

      ScepClient client = getScepClient();
      X509Cert caCert = client.getAuthorityCertStore().getCaCert();
      X500Name caSubject = caCert.getSubject();

      EnrolmentResponse resp = client.scepCertPoll(getIdentityKey(), getIdentityCert(), csr, caSubject);
      if (resp.isFailure()) {
        throw new CmdFailure("server returned 'failure'");
      } else if (resp.isPending()) {
        throw new CmdFailure("server returned 'pending'");
      }

      List<X509Cert> certs = resp.getCertificates();
      if (certs == null || certs.isEmpty()) {
        throw new CmdFailure("received no certficate from server");
      }

      saveVerbose("saved certificate to file", outputFile, encodeCert(certs.get(0).getEncoded(), outform));
      return null;
    }

  } // class ScepCertpoll

  public abstract static class ClientAction extends XiAction {

    @Option(name = "--url", required = true, description = "URL of the SCEP server")
    protected String url;

    @Option(name = "--ca-id", description = "CA identifier")
    protected String caId;

    @Option(name = "--ca-cert", required = true, description = "CA certificate")
    @Completion(FileCompleter.class)
    private String caCertFile;

    @Option(name = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FileCompleter.class)
    private String p12File;

    @Option(name = "--password", description = "password of the PKCS#12 keystore file")
    private String password;

    private ScepClient scepClient;
    private PrivateKey identityKey;
    private X509Cert identityCert;

    protected ScepClient getScepClient() throws CertificateException, IOException {
      if (scepClient == null) {
        X509Cert caCert = X509Util.parseCert(new File(caCertFile));
        CaIdentifier tmpCaId = new CaIdentifier(url, caId);
        CaCertValidator caCertValidator = new CaCertValidator.PreprovisionedCaCertValidator(caCert);
        scepClient = new ScepClient(tmpCaId, caCertValidator);
      }
      return scepClient;
    }

    protected PrivateKey getIdentityKey() throws Exception {
      if (identityKey == null) {
        readIdentity();
      }
      return identityKey;
    }

    protected X509Cert getIdentityCert() throws Exception {
      if (identityCert == null) {
        readIdentity();
      }

      return identityCert;
    }

    private void readIdentity() throws Exception {
      char[] pwd = readPasswordIfNotSet(password);

      KeyStore ks = KeyUtil.getKeyStore("PKCS12");
      try (InputStream is = Files.newInputStream(Paths.get(p12File))) {
        ks.load(is, pwd);
      }

      String keyname = null;
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (ks.isKeyEntry(alias)) {
          keyname = alias;
          break;
        }
      }

      if (keyname == null) {
        throw new Exception("no key entry is contained in the keystore");
      }

      this.identityKey = (PrivateKey) ks.getKey(keyname, pwd);
      this.identityCert = new X509Cert((X509Certificate) ks.getCertificate(keyname));
    }

  } // class ClientAction

  @Command(scope = "xi", name = "scep-enroll", description = "enroll certificate")
  @Service
  public static class ScepEnroll extends ClientAction {

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Option(name = "--method", description = "method to enroll the certificate.")
    @Completion(value = StringsCompleter.class, values = {"pkcs", "renewal"})
    private String method;

    @Override
    protected Object execute0() throws Exception {
      ScepClient client = getScepClient();

      CertificationRequest csr = X509Util.parseCsr(new File(csrFile));
      EnrolmentResponse resp;

      PrivateKey key0 = getIdentityKey();
      X509Cert cert0 = getIdentityCert();
      if (StringUtil.isBlank(method)) {
        resp = client.scepEnrol(csr, key0, cert0);
      } else if ("pkcs".equalsIgnoreCase(method)) {
        resp = client.scepPkcsReq(csr, key0, cert0);
      } else if ("renewal".equalsIgnoreCase(method)) {
        resp = client.scepRenewalReq(csr, key0, cert0);
      } else {
        throw new CmdFailure("invalid enroll method");
      }

      if (resp.isFailure()) {
        throw new CmdFailure("server returned 'failure'");
      }

      if (resp.isPending()) {
        throw new CmdFailure("server returned 'pending'");
      }

      X509Cert cert = resp.getCertificates().get(0);
      saveVerbose("saved enrolled certificate to file", outputFile, encodeCert(cert.getEncoded(), outform));
      return null;
    }

  } // class ScepEnroll

  @Command(scope = "xi", name = "scep-cacert", description = "get CA certificate")
  @Service
  public static class ScepCacert extends XiAction {

    @Option(name = "--url", required = true, description = "URL of the SCEP server")
    private String url;

    @Option(name = "--ca-id", description = "CA identifier")
    private String caId;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CA certificate")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Override
    protected Object execute0() throws Exception {
      CaIdentifier tmpCaId = new CaIdentifier(url, caId);
      CaCertValidator caCertValidator = new CaCertValidator() {
        @Override
        public boolean isTrusted(X509Cert cert) {
          return true;
        }
      };

      ScepClient client = new ScepClient(tmpCaId, caCertValidator);
      client.init();
      X509Cert caCert = client.getCaCert();
      if (caCert == null) {
        throw new CmdFailure("received no CA certficate from server");
      }

      saveVerbose("saved certificate to file", outFile, encodeCert(caCert.getEncoded(), outform));
      return null;
    }

  } // class ScepCacert

  @Command(scope = "xi", name = "scep-get-cert", description = "download certificate")
  @Service
  public static class ScepGetCert extends ClientAction {

    @Option(name = "--serial", aliases = "-s", required = true, description = "serial number")
    private String serialNumber;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      ScepClient client = getScepClient();
      BigInteger serial = toBigInt(serialNumber);
      X509Cert caCert = client.getAuthorityCertStore().getCaCert();
      X500Name caSubject = caCert.getSubject();
      List<X509Cert> certs = client.scepGetCert(getIdentityKey(), getIdentityCert(), caSubject, serial);
      if (certs == null || certs.isEmpty()) {
        throw new CmdFailure("received no certficate from server");
      }

      saveVerbose("saved certificate to file", new File(outputFile),
          encodeCert(certs.get(0).getEncoded(), outform));
      return null;
    }

  } // class ScepGetCert

  @Command(scope = "xi", name = "scep-get-crl", description = "download CRL")
  @Service
  public static class ScepGetCrl extends ClientAction {

    @Option(name = "--cert", aliases = "-c", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CRL")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      X509Cert cert = X509Util.parseCert(new File(certFile));
      ScepClient client = getScepClient();
      X509CRLHolder crl = client.scepGetCrl(getIdentityKey(), getIdentityCert(),
          cert.getIssuer(), cert.getSerialNumber());
      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outputFile, encodeCrl(crl.getEncoded(), outform));
      return null;
    }

  } // class ScepGetCrl

}
