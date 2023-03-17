// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.CertWithRevocationInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.security.CrlReason;
import org.xipki.security.KeyCertBytesPair;
import org.xipki.security.X509Cert;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.PemEncoder;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.List;

/**
 * Actions to management certificates and CRLs.
 *
 * @author Lijun Liao (xipki)
 *
 */
public class CertActions {

  @Command(scope = "ca", name = "cert-status", description = "show certificate status and save the certificate")
  @Service
  public static class CertStatus extends UnsuspendRmCertAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertWithRevocationInfo certInfo = caManager.getCert(caName, getSerialNumber());

      if (certInfo == null) {
        System.out.println("certificate unknown");
        return null;
      }

      String msg = StringUtil.concat("certificate profile: ", certInfo.getCertprofile(),
          "\nstatus: ", (certInfo.getRevInfo() == null ? "good" : "revoked with " + certInfo.getRevInfo()));
      println(msg);
      if (outputFile != null) {
        saveVerbose("saved certificate to file", outputFile,
            encodeCert(certInfo.getCert().getCert().getEncoded(), outform));
      }
      return null;
    } // method execute0

  } // class CertStatus

  public abstract static class CrlAction extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    protected abstract X509CRLHolder retrieveCrl() throws Exception;

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      X509CRLHolder crl;
      try {
        crl = retrieveCrl();
      } catch (Exception ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      String outFile = getOutFile();
      if (outFile != null) {
        saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
      }
      return null;
    } // method execute0

    protected abstract String getOutFile();

  } // class CrlAction

  @Command(scope = "ca", name = "enroll-cert", description = "enroll certificate")
  @Service
  public static class EnrollCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--subject", description = "Subject of the certificate.\n" +
        "Exactly one of subject (keypair generated by CA) or CSR must be specified.")
    protected String subject;

    @Option(name = "--csr", description = "The CSR file.\n" +
        "Exactly one of subject (keypair generated by CA) or csr must be specified.")
    @Completion(FileCompleter.class)
    protected String csrFile;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--key-outform", description = "output format of the private key (pem or p12)")
    protected String keyOutform = "p12";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Option(name = "--key-password",
        description = "Password to protect the private key, as plaintext or PBE-encrypted.\n" +
        "For key-outform PEM, NONE may be used to save the key in unecrypted form.")
    protected String keyPasswordHint;

    @Option(name = "--profile", aliases = "-p", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    protected String profileName;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    protected String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    protected String notAfterS;

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      if (StringUtil.isBlank(subject) == StringUtil.isBlank(csrFile)) {
        throw new IllegalCmdParamException(
            "Exactly one of subject (keypair generated by CA) or CSR must be specified.");
      }

      if (!StringUtil.orEqualsIgnoreCase(keyOutform, "pem", "p12", "pkcs12")) {
        throw  new IllegalCmdParamException("invalid key-outform " + keyOutform);
      }

      Date notBefore = parseDate(notBeforeS);
      Date notAfter = parseDate(notAfterS);

      byte[] certBytes;
      if (StringUtil.isNotBlank(csrFile)) {
        byte[] encodedCsr = StringUtil.isNotBlank(csrFile) ? X509Util.toDerEncoded(IoUtil.read(csrFile)) : null;
        certBytes = caManager.generateCertificate(caName, profileName, encodedCsr, notBefore, notAfter).getEncoded();
      } else {
        boolean needKeyPwd = true;
        if ("NONE".equalsIgnoreCase(keyPasswordHint)) {
          needKeyPwd = false;
          if (!"pem".equalsIgnoreCase(keyOutform)) {
            throw new IllegalCmdParamException("Password NONE is not allowed");
          }
        }

        char[] keyPwd = null;
        if (needKeyPwd) {
          keyPwd = readPasswordIfNotSet("Enter password to protect the private key", keyPasswordHint);
        }

        KeyCertBytesPair keyCertBytesPair =
            caManager.generateKeyCert(caName, profileName, subject, notBefore, notAfter);

        certBytes = keyCertBytesPair.getCert();

        String ksFilePrefix = outFile.substring(0, outFile.lastIndexOf('.'));

        PrivateKey privKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(keyCertBytesPair.getKey()));

        if (StringUtil.orEqualsIgnoreCase(keyOutform, "p12", "pkcs12")) {
          CertificateFactory cf = CertificateFactory.getInstance("X509");
          Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));

          KeyStore p12Ks = KeyUtil.getOutKeyStore("PKCS12");
          p12Ks.load(null, keyPwd);
          p12Ks.setKeyEntry("main", privKey, keyPwd, new Certificate[]{cert});

          byte[] ksBytes;
          try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            p12Ks.store(os, keyPwd);
            ksBytes = os.toByteArray();
          }

          saveVerbose("saved PKCS#12 keystore to file", ksFilePrefix + ".p12", ksBytes);
        } else {
          if (keyPwd == null) {
            saveVerbose("save unencrypted key to file", ksFilePrefix + "-key.pem",
                PemEncoder.encode(keyCertBytesPair.getKey(), PemEncoder.PemLabel.PRIVATE_KEY));
          } else {
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
                new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
            encryptorBuilder.setRandom(securityFactory.getRandom4Sign());
            encryptorBuilder.setPassword(keyPwd);
            JcaPKCS8Generator gen = new JcaPKCS8Generator(privKey, encryptorBuilder.build());
            PemObject obj = gen.generate();

            saveVerbose("save key to file", ksFilePrefix + "-key.pem",
                PemEncoder.encode(obj.getContent(), PemEncoder.PemLabel.ENCRYPTED_PRIVATE_KEY));
          }
        }
      }

      saveVerbose("saved certificate to file", outFile, encodeCert(certBytes, outform));
      return null;
    } // method execute0

  } // class EnrollCert

  @Command(scope = "ca", name = "enroll-cross-cert", description = "enroll cross certificate")
  @Service
  public static class EnrollCrossCert extends EnrollCert {

    @Option(name = "--target-cert", required = true, description =
            " certificate file, for which the cross certificate will be generated. There shall "
            + "be no difference in subject and public key between certFile and csrFile.")
    @Completion(FileCompleter.class)
    private String targetCertFile;

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      Date notBefore = parseDate(notBeforeS);
      Date notAfter = parseDate(notAfterS);

      byte[] encodedCsr = X509Util.toDerEncoded(IoUtil.read(csrFile));
      byte[] encodedTargetCert = X509Util.toDerEncoded(IoUtil.read(targetCertFile));

      X509Cert cert = caManager.generateCrossCertificate(caName, profileName,
          encodedCsr, encodedTargetCert, notBefore, notAfter);
      saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));

      return null;
    } // method execute0

  } // class EnrollCrossCert

  @Command(scope = "ca", name = "gen-crl", description = "generate CRL")
  @Service
  public static class GenCrl extends CrlAction {

    @Option(name = "--out", aliases = "-o", description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Override
    protected X509CRLHolder retrieveCrl() throws Exception {
      return caManager.generateCrlOnDemand(caName);
    }

    @Override
    protected String getOutFile() {
      return outFile;
    }

  } // class GenCrl

  @Command(scope = "ca", name = "get-cert", description = "get certificate")
  @Service
  public static class GetCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--serial", aliases = "-s", required = true, description = "serial number")
    private String serialNumberS;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertWithRevocationInfo certInfo = caManager.getCert(caName, toBigInt(serialNumberS));

      if (certInfo == null) {
        System.out.println("certificate unknown");
        return null;
      }

      saveVerbose("certificate saved to file", outputFile,
          encodeCert(certInfo.getCert().getCert().getEncoded(), outform));
      return null;
    } // method execute0

  } // class GetCert

  @Command(scope = "ca", name = "get-crl", description = "download CRL")
  @Service
  public static class GetCrl extends CrlAction {

    @Option(name = "--with-basecrl", description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
    private Boolean withBaseCrl = Boolean.FALSE;

    @Option(name = "--basecrl-out", description = "where to save the baseCRL\n(defaults to <out>-baseCRL)")
    @Completion(FileCompleter.class)
    private String baseCrlOut;

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Override
    protected X509CRLHolder retrieveCrl() throws Exception {
      return caManager.getCurrentCrl(caName);
    }

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      X509CRLHolder crl;
      try {
        crl = retrieveCrl();
      } catch (Exception ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));

      if (withBaseCrl) {
        Extensions extns = crl.getExtensions();
        byte[] extnValue = X509Util.getCoreExtValue(extns, Extension.deltaCRLIndicator);
        if (extnValue != null) {
          if (baseCrlOut == null) {
            baseCrlOut = outFile + "-baseCRL";
          }

          BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

          try {
            crl = caManager.getCrl(caName, baseCrlNumber);
          } catch (Exception ex) {
            throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
          }

          if (crl == null) {
            throw new CmdFailure("received no baseCRL from server");
          } else {
            saveVerbose("saved baseCRL to file", baseCrlOut, encodeCrl(crl.getEncoded(), outform));
          }
        }
      }

      return null;
    } // method execute0

    @Override
    protected String getOutFile() {
      return outFile;
    }

  } // class GetCrl

  @Command(scope = "ca", name = "list-cert", description = "show a list of certificates")
  @Service
  public static class ListCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--subject", description = "the subject pattern, * is allowed.")
    protected String subjectPatternS;

    @Option(name = "--valid-from",
        description = "start UTC time when the certificate is still valid, in form of yyyyMMdd or yyyyMMddHHmmss")
    private String validFromS;

    @Option(name = "--valid-to",
        description = "end UTC time when the certificate is still valid, in form of yyyMMdd or yyyyMMddHHmmss")
    private String validToS;

    @Option(name = "-n", description = "maximal number of entries (between 1 and 1000)")
    private int num = 1000;

    @Option(name = "--order", description = "by which the result is ordered")
    @Completion(CaCompleters.CertListSortByCompleter.class)
    private String orderByS;

    @Override
    protected Object execute0() throws Exception {
      X500Name subjectPattern = StringUtil.isBlank(subjectPatternS) ? null : new X500Name(subjectPatternS);

      CertListOrderBy orderBy = null;
      if (orderByS != null) {
        orderBy = CertListOrderBy.forValue(orderByS);
        if (orderBy == null) {
          throw new IllegalCmdParamException("invalid order '" + orderByS + "'");
        }
      }

      List<CertListInfo> certInfos =
          caManager.listCertificates(caName, subjectPattern, parseDate(validFromS), parseDate(validToS), orderBy, num);
      final int n = certInfos.size();
      if (n == 0) {
        println("found no certificate");
        return null;
      }

      println("     | serial               | notBefore      | notAfter       | subject");
      println("-----+----------------------+----------------+----------------+-----------------");
      for (int i = 0; i < n; i++) {
        println(format(i + 1, certInfos.get(i)));
      }

      return null;
    } // method execute0

    private String format(int index, CertListInfo info) {
      return StringUtil.concat(StringUtil.formatAccount(index, 4), " | ",
          StringUtil.formatText(info.getSerialNumber().toString(16), 20), " | ",
          DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotBefore()), " | ",
          DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotAfter()), " | ", info.getSubject());
    } // method format

  } // class ListCert

  @Command(scope = "ca", name = "rm-cert", description = "remove certificate")
  @Service
  public static class RmCert extends UnsuspendRmCertAction {

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCertificate(caName, serialNo);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    } // method execute0

  } // class RmCert

  @Command(scope = "ca", name = "revoke-cert", description = "revoke certificate")
  @Service
  public static class RevokeCert extends UnsuspendRmCertAction {

    @Option(name = "--reason", aliases = "-r", required = true, description = "CRL reason")
    @Completion(Completers.ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
        throw new InvalidConfException("reason " + reason + " is not permitted");
      }

      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      try {
        caManager.revokeCertificate(caName, serialNo, crlReason, parseDate(invalidityDateS));
        println("revoked " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not revoke " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class RevokeCert

  @Command(scope = "ca", name = "unsuspend-cert", description = "unsuspend certificate")
  @Service
  public static class UnsuspendCert extends UnsuspendRmCertAction {

    @Override
    protected Object execute0() throws Exception {
      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      try {
        caManager.unsuspendCertificate(caName, serialNo);
        println("unsuspended " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not unsuspend " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class UnrevokeCert

  public abstract static class UnsuspendRmCertAction extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--cert", aliases = "-c",
        description = "certificate file\n(either cert or serial must be specified)")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s", description = "serial number\n(either cert or serial must be specified)")
    private String serialNumberS;

    protected BigInteger getSerialNumber() throws Exception  {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      BigInteger serialNumber;
      if (serialNumberS != null) {
        serialNumber = toBigInt(serialNumberS);
      } else if (certFile != null) {
        X509Cert caCert = ca.getCert();
        X509Cert cert = X509Util.parseCert(new File(certFile));
        if (!X509Util.issues(caCert, cert)) {
          throw new CmdFailure("certificate '" + certFile + "' is not issued by CA " + caName);
        }
        serialNumber = cert.getSerialNumber();
      } else {
        throw new IllegalCmdParamException("neither serialNumber nor certFile is specified");
      }

      return serialNumber;
    } // method getSerialNumber

  } // class UnRevRmCertAction

}
