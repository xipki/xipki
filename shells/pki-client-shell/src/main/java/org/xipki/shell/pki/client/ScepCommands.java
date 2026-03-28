// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.xipki.scep.client.CaIdentifier;
import org.xipki.scep.client.EnrolmentResponse;
import org.xipki.scep.client.ScepClient;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.List;

/**
 * SCEP client commands.
 *
 * @author Lijun Liao (xipki)
 */
public class ScepCommands {
  abstract static class ScepClientCommand extends ShellBaseCommand {

    private static final class Identity {
      private final PrivateKey privateKey;
      private final X509Cert certificate;

      private Identity(PrivateKey privateKey, X509Cert certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
      }
    }

    @Option(names = "--url", required = true, description = "URL of the SCEP server")
    protected String url;

    @Option(names = "--ca-id", description = "CA identifier")
    protected String caId;

    @Option(names = "--ca-cert", required = true, description = "CA certificate")
    @Completion(FilePathCompleter.class)
    private String caCertFile;

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 keystore file")
    private String passwordHint;

    protected ScepClient getScepClient() throws Exception {
      return PkiClientRuntime.getScepClient(url, caId, caCertFile);
    }

    protected PrivateKey getIdentityKey() throws Exception {
      return readIdentity().privateKey;
    }

    protected X509Cert getIdentityCert() throws Exception {
      return readIdentity().certificate;
    }

    private Identity readIdentity() throws Exception {
      char[] pwd = passwordHint == null
          ? readPassword("Enter the keystore password")
          : Passwords.resolvePassword(passwordHint);
      PKCS12KeyStore ks;
      try (InputStream is = Files.newInputStream(Paths.get(p12File))) {
        ks = KeyUtil.loadPKCS12KeyStore(is, pwd);
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
        throw new IOException("no key entry is contained in the keystore");
      }

      PrivateKey identityKey = KeyUtil.getPrivateKey(ks.getKey(keyname));
      X509Cert identityCert = new X509Cert(ks.getCertificate(keyname));
      return new Identity(identityKey, identityCert);
    }
  }

  @Command(name = "scep-certpoll", description = "poll certificate",
      mixinStandardHelpOptions = true)
  static class ScepCertpollCommand extends ScepClientCommand {

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    public void run() {
      try {
        CertificationRequest csr = X509Util.parseCsr(new File(csrFile));
        ScepClient client = getScepClient();
        X509Cert caCert = client.authorityCertStore().caCert();
        X500Name caSubject = caCert.subject();

        EnrolmentResponse resp = client.scepCertPoll(
            getIdentityKey(), getIdentityCert(), csr, caSubject);
        if (resp.isFailure()) {
          throw new IOException("server returned 'failure'");
        } else if (resp.isPending()) {
          throw new IOException("server returned 'pending'");
        }

        List<X509Cert> certs = resp.certificates();
        if (CollectionUtil.isEmpty(certs)) {
          throw new IOException("received no certificate from server");
        }

        saveVerbose("saved certificate to file", outputFile,
            encodeCert(certs.get(0).getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "scep-enroll", description = "enroll certificate",
      mixinStandardHelpOptions = true)
  static class ScepEnrollCommand extends ScepClientCommand {

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Option(names = "--method", description = "method to enroll the certificate")
    @Completion(values = {"pkcs", "renewal"})
    private String method;

    @Override
    public void run() {
      try {
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
          throw new IOException("invalid enroll method");
        }

        if (resp.isFailure()) {
          throw new IOException("server returned 'failure'");
        }
        if (resp.isPending()) {
          throw new IOException("server returned 'pending'");
        }

        X509Cert cert = resp.certificates().get(0);
        saveVerbose("saved enrolled certificate to file", outputFile,
            encodeCert(cert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "scep-cacert", description = "get CA certificate",
      mixinStandardHelpOptions = true)
  static class ScepCacertCommand extends ShellBaseCommand {

    @Option(names = "--url", required = true, description = "URL of the SCEP server")
    private String url;

    @Option(names = "--ca-id", description = "CA identifier")
    private String caId;

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true,
        description = "where to save the CA certificate")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        ScepClient client = new ScepClient(new CaIdentifier(url, caId), cert -> true);
        client.init();
        X509Cert caCert = client.caCert();
        if (caCert == null) {
          throw new IOException("received no CA certificate from server");
        }

        saveVerbose("saved certificate to file", outFile,
            encodeCert(caCert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "scep-get-cert", description = "download certificate",
      mixinStandardHelpOptions = true)
  static class ScepGetCertCommand extends ScepClientCommand {

    @Option(names = {"--serial", "-s"}, required = true, description = "serial number")
    private String serialNumber;

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    public void run() {
      try {
        ScepClient client = getScepClient();
        BigInteger serial = toBigInt(serialNumber);
        X509Cert caCert = client.authorityCertStore().caCert();
        X500Name caSubject = caCert.subject();
        List<X509Cert> certs = client.scepGetCert(
            getIdentityKey(), getIdentityCert(), caSubject, serial);
        if (CollectionUtil.isEmpty(certs)) {
          throw new IOException("received no certificate from server");
        }

        saveVerbose("saved certificate to file", outputFile,
            encodeCert(certs.get(0).getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "scep-get-crl", description = "download CRL", mixinStandardHelpOptions = true)
  static class ScepGetCrlCommand extends ScepClientCommand {

    @Option(names = {"--cert", "-c"}, required = true, description = "certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--outform", description = "output format of the CRL")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the CRL")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    public void run() {
      try {
        X509Cert cert = X509Util.parseCert(new File(certFile));
        X509CRLHolder crl = getScepClient().scepGetCrl(
            getIdentityKey(), getIdentityCert(), cert.issuer(), cert.serialNumber());
        if (crl == null) {
          throw new IOException("received no CRL from server");
        }

        saveVerbose("saved CRL to file", outputFile, encodeCrl(crl.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }
}
