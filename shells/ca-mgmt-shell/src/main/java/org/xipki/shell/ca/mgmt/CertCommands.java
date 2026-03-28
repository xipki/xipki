// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertStatistics;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.security.OIDs;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.KeyCertBytesPair;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.pkix.X509Crl;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.json.JsonBuilder;
import org.xipki.util.extra.misc.PemEncoder;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Actions to management certificates and CRLs.
 *
 * @author Lijun Liao (xipki)
 */
public class CertCommands {
  @Command(name = "cert-status", description = "show certificate status and save the certificate",
      mixinStandardHelpOptions = true)
  static class CertStatusCommand extends CertBySerialCommand {

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    public void run() {
      try {
        CertWithRevocationInfo certInfo = client().getCert(caName, getSerialNumber());
        if (certInfo == null) {
          println("certificate unknown");
          return;
        }
        println("certificate profile: " + certInfo.certprofile() + "\nstatus: "
            + (certInfo.revInfo() == null ? "good" : "revoked with " + certInfo.revInfo()));
        if (outputFile != null) {
          saveVerbose("saved certificate to file", outputFile,
              encodeCert(certInfo.cert().cert().getEncoded(), outform));
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not get certificate status: " + ex.getMessage(), ex);
      }
    }
  }

  abstract static class CrlCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    protected String outform = "der";

    protected abstract X509Crl retrieveCrl() throws Exception;

    protected abstract String getOutFile();

    @Override
    public void run() {
      try {
        Optional.ofNullable(client().getCa(caName))
            .orElseThrow(() -> new CaMgmtException("CA " + caName + " not available"));
        X509Crl crl = Optional.ofNullable(retrieveCrl())
            .orElseThrow(() -> new CaMgmtException("received no CRL from server"));
        String outFile = getOutFile();
        if (outFile != null) {
          saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not retrieve CRL: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "gen-crl", description = "generate CRL", mixinStandardHelpOptions = true)
  static class GenCrlCommand extends CrlCommand {

    @Option(names = {"--out", "-o"}, description = "where to save the CRL")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    protected X509Crl retrieveCrl() throws Exception {
      return client().generateCrlOnDemand(caName);
    }

    @Override
    protected String getOutFile() {
      return outFile;
    }
  }

  @Command(name = "get-cert", description = "get certificate", mixinStandardHelpOptions = true)
  static class GetCertCommand extends CertBySerialCommand {

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Override
    public void run() {
      try {
        CertWithRevocationInfo certInfo = client().getCert(caName, getSerialNumber());
        if (certInfo == null) {
          println("certificate unknown");
          return;
        }
        saveVerbose("certificate saved to file", outputFile,
            encodeCert(certInfo.cert().cert().getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException("could not get certificate: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "get-crl", description = "download CRL", mixinStandardHelpOptions = true)
  static class GetCrlCommand extends CrlCommand {

    @Option(names = "--with-basecrl", description = "retrieve baseCRL if current CRL is delta CRL")
    private boolean withBaseCrl;

    @Option(names = "--basecrl-out", description = "where to save the baseCRL")
    @Completion(FilePathCompleter.class)
    private String baseCrlOut;

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the CRL")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    protected X509Crl retrieveCrl() throws Exception {
      return client().getCurrentCrl(caName);
    }

    @Override
    public void run() {
      try {
        X509Crl crl = Optional.ofNullable(client().getCurrentCrl(caName))
            .orElseThrow(() -> new CaMgmtException("received no CRL from server"));
        saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));

        if (withBaseCrl) {
          byte[] extnValue = X509Util.getCoreExtValue(crl.extensions(),
                                OIDs.Extn.deltaCRLIndicator);
          if (extnValue != null) {
            if (baseCrlOut == null) {
              baseCrlOut = outFile + "-baseCRL";
            }
            BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();
            X509Crl base = Optional.ofNullable(client().getCrl(caName, baseCrlNumber))
                .orElseThrow(() -> new CaMgmtException("received no baseCRL from server"));
            saveVerbose("saved baseCRL to file", baseCrlOut,
                encodeCrl(base.getEncoded(), outform));
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not get CRL: " + ex.getMessage(), ex);
      }
    }

    @Override
    protected String getOutFile() {
      return outFile;
    }
  }

  @Command(name = "list-cert", description = "show a list of certificates",
      mixinStandardHelpOptions = true)
  static class ListCertCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--subject", description = "subject pattern, * is allowed")
    private String subjectPatternS;

    @Option(names = "--valid-from", description = "start UTC time yyyyMMdd or yyyyMMddHHmmss")
    private String validFromS;

    @Option(names = "--valid-to", description = "end UTC time yyyyMMdd or yyyyMMddHHmmss")
    private String validToS;

    @Option(names = "-n", description = "maximal number of entries")
    private int num = 1000;

    @Option(names = "--order", description = "ordering")
    private String orderByS;

    @Override
    public void run() {
      try {
        X500Name subjectPattern = StringUtil.isBlank(subjectPatternS)
            ? null : new X500Name(subjectPatternS);
        CertListOrderBy orderBy = orderByS == null ? null : CertListOrderBy.forValue(orderByS);
        if (orderByS != null && orderBy == null) {
          throw new IllegalArgumentException("invalid order '" + orderByS + "'");
        }

        List<CertListInfo> certInfos = client().listCertificates(caName, subjectPattern,
            CaMgmtUtil.parseDate(validFromS), CaMgmtUtil.parseDate(validToS), orderBy, num);
        if (certInfos.isEmpty()) {
          println("found no certificate");
          return;
        }
        println("     |                    serial                |    notBefore   |"
            + "    notAfter    |         subject");
        println("-----+------------------------------------------+----------------+"
            + "----------------+---------------------------");
        for (int i = 0; i < certInfos.size(); i++) {
          println(CaMgmtUtil.formatCertListLine(i + 1, certInfos.get(i)));
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not list certificates: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "rm-cert", description = "remove certificate", mixinStandardHelpOptions = true)
  public static class RmCertCommand extends CertBySerialCommand {

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        BigInteger serialNo = getSerialNumber();
        String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
        if (force || confirmAction("Do you want to remove " + msg)) {
          client().removeCertificate(caName, serialNo);
          println("removed " + msg);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove certificate: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "revoke-cert", description = "revoke certificate",
      mixinStandardHelpOptions = true)
  public static class RevokeCertCommand extends CertBySerialCommand {

    @Option(names = {"--reason", "-r"}, required = true, description = "CRL reason")
    @Completion(Completers.CrlReasonCompleter.class)
    private String reason;

    @Option(names = "--inv-date", description = "invalidity date UTC yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    public void run() {
      try {
        CrlReason crlReason = CrlReason.forNameOrText(reason);
        if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
          throw new IllegalArgumentException("reason " + reason + " is not permitted");
        }

        BigInteger serialNo = getSerialNumber();
        client().revokeCertificate(caName, serialNo, crlReason,
            CaMgmtUtil.parseDate(invalidityDateS));
        println("revoked certificate (serial number = 0x" + serialNo.toString(16) + ")");
      } catch (Exception ex) {
        throw new RuntimeException("could not revoke certificate: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "unsuspend-cert", description = "unsuspend certificate",
      mixinStandardHelpOptions = true)
  public static class UnsuspendCertCommand extends CertBySerialCommand {

    @Override
    public void run() {
      try {
        BigInteger serialNo = getSerialNumber();
        client().unsuspendCertificate(caName, serialNo);
        println("unsuspended certificate (serial number = 0x" + serialNo.toString(16) + ")");
      } catch (Exception ex) {
        throw new RuntimeException("could not unsuspend certificate: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "enroll-cert", description = "enroll certificate",
      mixinStandardHelpOptions = true)
  public static class EnrollCertCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(names = "--subject", description = "subject of the certificate")
    protected String subject;

    @Option(names = "--csr", description = "CSR file")
    @Completion(FilePathCompleter.class)
    protected String csrFile;

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    protected String outform = "der";

    @Option(names = "--key-outform", description = "private key format pem or p12")
    @Completion(FilePathCompleter.class)
    protected String keyOutform = "p12";

    @Option(names = {"--out", "-o"}, required = true, description = "certificate output file")
    @Completion(FilePathCompleter.class)
    protected String outFile;

    @Option(names = "--key-password", description = "key password or password hint")
    protected String keyPasswordHint;

    @Option(names = {"--profile", "-p"}, required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    protected String profileName;

    @Option(names = "--not-before", description = "notBefore UTC yyyyMMddHHmmss")
    @Completion(Completers.YesNoCompleter.class)
    protected String notBeforeS;

    @Option(names = "--not-after", description = "notAfter UTC yyyyMMddHHmmss")
    @Completion(Completers.YesNoCompleter.class)
    protected String notAfterS;

    @Override
    public void run() {
      try {
        Optional.ofNullable(client().getCa(caName))
            .orElseThrow(() -> new CaMgmtException("CA " + caName + " not available"));
        if (StringUtil.isBlank(subject) == StringUtil.isBlank(csrFile)) {
          throw new IllegalArgumentException("Exactly one of subject or CSR must be specified.");
        }
        if (!StringUtil.orEqualsIgnoreCase(keyOutform, "pem", "p12", "pkcs12")) {
          throw new IllegalArgumentException("invalid key-outform " + keyOutform);
        }

        Instant notBefore = CaMgmtUtil.parseDate(notBeforeS);
        Instant notAfter = CaMgmtUtil.parseDate(notAfterS);
        byte[] certBytes;
        if (StringUtil.isNotBlank(csrFile)) {
          byte[] encodedCsr = X509Util.toDerEncoded(IoUtil.read(csrFile));
          certBytes = client().generateCertificate(
              caName, profileName, encodedCsr, notBefore, notAfter).getEncoded();
        } else {
          boolean needKeyPwd = true;
          if ("NONE".equalsIgnoreCase(keyPasswordHint)) {
            needKeyPwd = false;
            if (!"pem".equalsIgnoreCase(keyOutform)) {
              throw new IllegalArgumentException("Password NONE is not allowed");
            }
          }

          char[] keyPwd = needKeyPwd
              ? readPasswordIfNotSet("Enter password to protect the private key",
                  keyPasswordHint)
              : null;
          KeyCertBytesPair keyCertBytesPair = client().generateKeyCert(
              caName, profileName, subject, notBefore, notAfter);
          certBytes = keyCertBytesPair.cert();
          saveGeneratedKey(outFile, keyOutform, keyPwd, keyCertBytesPair);
        }

        saveVerbose("saved certificate to file", outFile, encodeCert(certBytes, outform));
      } catch (Exception ex) {
        throw new RuntimeException("could not enroll certificate: " + ex.getMessage(), ex);
      }
    }

    protected void saveGeneratedKey(
        String certOutFile, String keyOutform, char[] keyPwd, KeyCertBytesPair pair)
        throws Exception {
      String ksFilePrefix = certOutFile.substring(0, certOutFile.lastIndexOf('.'));
      PrivateKeyInfo privKeyInfo = PrivateKeyInfo.getInstance(pair.key());
      if (StringUtil.orEqualsIgnoreCase(keyOutform, "p12", "pkcs12")) {
        Certificate cert = Certificate.getInstance(pair.cert());
        PKCS12KeyStore p12Ks = KeyUtil.loadPKCS12KeyStore(null, keyPwd);
        p12Ks.setKeyEntry("main", privKeyInfo, cert);
        byte[] ksBytes;
        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
          p12Ks.store(os, keyPwd);
          ksBytes = os.toByteArray();
        }
        saveVerbose("saved PKCS#12 keystore to file", ksFilePrefix + ".p12", ksBytes);
      } else if (keyPwd == null) {
        saveVerbose("save unencrypted key to file", ksFilePrefix + "-key.pem",
            PemEncoder.encode(pair.key(), PemEncoder.PemLabel.PRIVATE_KEY));
      } else {
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
            new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
        encryptorBuilder.setRandom(SecureRandom.getInstanceStrong());
        encryptorBuilder.setPassword(keyPwd);
        JcaPKCS8Generator generator = new JcaPKCS8Generator(
            KeyUtil.getPrivateKey(privKeyInfo), encryptorBuilder.build());
        PemObject obj = generator.generate();
        saveVerbose("save key to file", ksFilePrefix + "-key.pem",
            PemEncoder.encode(obj.getContent(), PemEncoder.PemLabel.ENCRYPTED_PRIVATE_KEY));
      }
    }
  }

  @Command(name = "enroll-cross-cert", description = "enroll cross certificate",
      mixinStandardHelpOptions = true)
  static class EnrollCrossCertCommand extends EnrollCertCommand {

    @Option(names = "--target-cert", required = true, description = "target certificate file")
    @Completion(FilePathCompleter.class)
    private String targetCertFile;

    @Override
    public void run() {
      try {
        Optional.ofNullable(client().getCa(caName))
            .orElseThrow(() -> new CaMgmtException("CA " + caName + " not available"));
        X509Cert cert = client().generateCrossCertificate(
            caName, profileName, X509Util.toDerEncoded(IoUtil.read(csrFile)),
            X509Util.toDerEncoded(IoUtil.read(targetCertFile)),
            CaMgmtUtil.parseDate(notBeforeS), CaMgmtUtil.parseDate(notAfterS));
        saveVerbose("saved certificate to file", outFile,
            encodeCert(cert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException("could not enroll cross certificate: " + ex.getMessage(), ex);
      }
    }
  }

  abstract static class CertBySerialCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(names = {"--cert", "-c"}, description = "certificate file")
    @Completion(FilePathCompleter.class)
    protected String certFile;

    @Option(names = {"--serial", "-s"}, description = "serial number")
    private String serialNumberS;

    protected BigInteger getSerialNumber() throws Exception {
      CaEntry ca = client().getCa(caName);
      if (ca == null) {
        throw new CaMgmtException("CA " + caName + " not available");
      }

      if (serialNumberS != null) {
        return toBigInt(serialNumberS);
      } else if (certFile != null) {
        X509Cert cert = X509Util.parseCert(new File(certFile));
        if (!X509Util.issues(ca.cert(), cert)) {
          throw new CaMgmtException("certificate '" + certFile + "' is not issued by CA " + caName);
        }
        return cert.serialNumber();
      } else {
        throw new IllegalArgumentException("neither serialNumber nor certFile is specified");
      }
    }
  }

  @Command(name = "cert-statistics", description = "show statistics data of certificates",
      mixinStandardHelpOptions = true)
  public static class ShowCertStatistics extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--from", description =
        "The start time, in format YYYYMM. from and to shall be both present or both null.")
    private String from;

    @Option(names = "--to", description =
        "The end time, in format YYYYMM. from and to shall be both present or both null.")
    private String to;

    @Option(names = "--revoked", description = "Only revoked certificates")
    private Boolean revoked;

    @Option(names = "--ca", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private List<String> cas;

    @Option(names = "--profile", description = "Certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profiles;

    @Option(names = "--requestor", description = "Requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private List<String> requestors;

    @Override
    public void run() {
      try {
        if (from == null ^ to == null) {
          throw new IllegalArgumentException("from and to shall be both present or both null");
        }

        boolean revokedOnly = revoked != null && revoked;

        CertStatistics statistics = client().getCertStatistics(
            from, to, revokedOnly, cas, profiles, requestors);

        if (statistics == null) {
          System.out.println("ERROR");
        }

        System.out.println(JsonBuilder.toPrettyJson(statistics.toCodec()));
      } catch (Exception ex) {
        throw new RuntimeException("could not show certificate statics: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class ShowCertStatistics
}
