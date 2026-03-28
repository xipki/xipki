// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.xipki.cmp.client.CertIdOrError;
import org.xipki.cmp.client.CmpClient;
import org.xipki.cmp.client.EnrollCertRequest;
import org.xipki.cmp.client.EnrollCertResult;
import org.xipki.cmp.client.Requestor;
import org.xipki.cmp.client.RevokeCertRequest;
import org.xipki.cmp.client.UnsuspendCertRequest;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.cmp.PkiStatusInfo;
import org.xipki.security.pkcs12.PKCS12KeyStore;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.sign.ConcurrentSigner;
import org.xipki.security.sign.SignAlgoMode;
import org.xipki.security.sign.Signer;
import org.xipki.security.sign.SignerConf;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.misc.ReqRespDebug;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.Passwords;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * CMP client commands.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpCommands {
  abstract static class AuthCmpClientCommand extends CmpClientCommand {

    @Option(names = "--signer-p12", description = "signer PKCS#12 file")
    @Completion(FilePathCompleter.class)
    private String signerP12File;

    @Option(names = "--signer-p12-algo", description = "signature algorithm of the PKCS#12 signer")
    @Completion(FilePathCompleter.class)
    private String signerP12SigAlgo;

    @Option(names = "--signer-keyid", description = "user, text key ID, or 0x-prefixed hex key ID")
    private String signerKeyId;

    @Option(names = "--signer-password", description = "signer password")
    private String signerPasswordHint;

    protected Requestor getRequestor() throws Exception {
      if ((signerP12File == null) == (signerKeyId == null)) {
        throw new IllegalArgumentException(
            "exactly one of signer-p12 and signer-keyid must be specified");
      }

      if (signerP12File != null) {
        if (signerPasswordHint == null) {
          signerPasswordHint = new String(readPassword("Enter the password for " + signerP12File));
        }

        SignerConf signerConf = new SignerConf()
            .setPassword(signerPasswordHint).setKeystore("file:" + signerP12File);
        if (signerP12SigAlgo != null) {
          try {
            signerConf.setAlgo(SignAlgo.getInstance(signerP12SigAlgo));
          } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
          }
        }

        ConcurrentSigner signer = PkiClientRuntime.getSecurities()
            .securityFactory().createSigner("PKCS12", signerConf, (X509Cert) null);
        return new Requestor.SignatureCmpRequestor(signer);
      } else {
        if (signerPasswordHint == null) {
          signerPasswordHint = new String(
              readPassword("Enter the password for the user/keyID " + signerKeyId));
        }
        byte[] senderKID = StringUtil.startsWithIgnoreCase(signerKeyId, "0x")
            ? Hex.decode(signerKeyId) : signerKeyId.getBytes(StandardCharsets.UTF_8);
        return new Requestor.PbmMacCmpRequestor(
            Passwords.resolvePassword(signerPasswordHint),
            senderKID, HashAlgo.SHA256, 2048, SignAlgo.HMAC_SHA256);
      }
    }
  }

  @Command(name = "cmp-cacert", description = "get CA certificate", mixinStandardHelpOptions = true)
  static class CmpCaCertCommand extends CmpClientCommand {

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
        ReqRespDebug debug = getReqRespDebug();
        X509Cert caCert;
        try {
          caCert = client().caCert(caName, debug);
        } finally {
          saveRequestResponse(debug);
        }

        if (caCert == null) {
          throw new IOException("received no CA certificate");
        }
        saveVerbose("saved CA certificate to file", outFile,
            encodeCert(caCert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-cacerts", description = "get CA certificate chain",
      mixinStandardHelpOptions = true)
  static class CmpCaCertsCommand extends CmpClientCommand {

    @Option(names = {"--out", "-o"}, required = true,
        description = "where to save the CA certificate chain")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        ReqRespDebug debug = getReqRespDebug();
        List<X509Cert> caCertChain;
        try {
          caCertChain = client().caCerts(caName, debug);
        } finally {
          saveRequestResponse(debug);
        }

        if (CollectionUtil.isEmpty(caCertChain)) {
          throw new IOException("received no CA certificate chain");
        }

        String encoded = X509Util.encodeCertificates(caCertChain.toArray(new X509Cert[0]));
        saveVerbose("saved CA certificate to file", outFile,
            StringUtil.toUtf8Bytes(encoded));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-get-crl", description = "download CRL", mixinStandardHelpOptions = true)
  static class CmpGetCrlCommand extends CmpClientCommand {

    @Option(names = "--outform", description = "output format of the CRL")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the CRL")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        ReqRespDebug debug = getReqRespDebug();
        X509CRLHolder crl;
        try {
          crl = client().downloadCrl(caName, debug);
        } finally {
          saveRequestResponse(debug);
        }

        if (crl == null) {
          throw new IOException("received no CRL from server");
        }
        saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-revoke", description = "revoke certificate", mixinStandardHelpOptions = true)
  static class CmpRevokeCommand extends UnRevokeCertCommand {

    @Option(names = {"--reason", "-r"}, required = true, description = "CRL reason")
    @Completion(Completers.CrlReasonCompleter.class)
    private String reason;

    @Option(names = "--inv-date", description = "invalidity date yyyyMMddHHmmss UTC")
    private String invalidityDateS;

    @Override
    public void run() {
      try {
        CrlReason crlReason = CrlReason.forNameOrText(reason);
        if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
          throw new IllegalArgumentException("reason " + reason + " is not permitted");
        }

        Instant invalidityDate = StringUtil.isBlank(invalidityDateS)
            ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
        ReqInfo reqInfo = getReqInfo();

        ReqRespDebug debug = getReqRespDebug();
        Map<String, CertIdOrError> certIdOrErrors;
        try {
          Requestor requestor = getRequestor();
          RevokeCertRequest req = new RevokeCertRequest();
          for (int i = 0; i < reqInfo.ids.size(); i++) {
            RevokeCertRequest.Entry entry = new RevokeCertRequest.Entry(
                reqInfo.ids.get(i), reqInfo.caCert.subject(),
                reqInfo.serialNumbers.get(i), crlReason.code(), invalidityDate);
            req.addRequestEntry(entry);
          }
          certIdOrErrors = client().revokeCerts(caName, requestor, req, debug);
        } finally {
          saveRequestResponse(debug);
        }

        analyseResult(true, certIdOrErrors, reqInfo);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-unsuspend", description = "unsuspend certificate",
      mixinStandardHelpOptions = true)
  static class CmpUnsuspendCommand extends UnRevokeCertCommand {

    @Override
    public void run() {
      try {
        ReqInfo reqInfo = getReqInfo();
        ReqRespDebug debug = getReqRespDebug();
        Map<String, CertIdOrError> certIdOrErrors;
        try {
          Requestor requestor = getRequestor();
          UnsuspendCertRequest req = new UnsuspendCertRequest();
          for (int i = 0; i < reqInfo.ids.size(); i++) {
            UnsuspendCertRequest.Entry entry = new UnsuspendCertRequest.Entry(
                reqInfo.ids.get(i), reqInfo.caCert.subject(), reqInfo.serialNumbers.get(i));
            req.addRequestEntry(entry);
          }
          certIdOrErrors = client().unsuspendCerts(caName, requestor, req, debug);
        } finally {
          saveRequestResponse(debug);
        }
        analyseResult(false, certIdOrErrors, reqInfo);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-csr-enroll", description = "enroll certificate via CSR",
      mixinStandardHelpOptions = true)
  static class CmpCsrEnrollCommand extends AuthCmpClientCommand {

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = {"--profile", "-p"}, required = true, description = "certificate profile")
    private String profile;

    @Option(names = "--not-before", description = "notBefore yyyyMMddHHmmss UTC")
    private String notBeforeS;

    @Option(names = "--not-after", description = "notAfter yyyyMMddHHmmss UTC")
    private String notAfterS;

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
        Instant notBefore = StringUtil.isNotBlank(notBeforeS)
            ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;
        Instant notAfter = StringUtil.isNotBlank(notAfterS)
            ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;

        ReqRespDebug debug = getReqRespDebug();
        EnrollCertResult result;
        try {
          result = client().enrollCert(caName, getRequestor(), csr, profile,
              notBefore, notAfter, debug);
        } finally {
          saveRequestResponse(debug);
        }

        EnrollCertResult.CertifiedKeyPairOrError certOrError = firstEnrollResult(result);
        if (certOrError == null) {
          throw new IOException("error, received neither certificate nor error");
        } else if (certOrError.error() != null) {
          throw new IOException(certOrError.error().toString());
        }

        saveVerbose("certificate saved to file", outputFile,
            encodeCert(certOrError.certificate().getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cmp-enroll-serverkeygen",
      description = "enroll certificate (keypair will be generated by the CA)",
      mixinStandardHelpOptions = true)
  static class CmpEnrollServerkeygenCommand extends AbstractEnrollCommand {

    @Option(names = "--cmpreq-type", description = "CMP request type: ir or cr")
    @Completion(values = {"ir", "cr"})
    private String cmpreqType = "cr";

    @Option(names = "--cert-outform", description = "output format of the certificate")
    @Completion(FilePathCompleter.class)
    private String certOutform = "der";

    @Option(names = "--cert-out", description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certOutputFile;

    @Option(names = "--p12-out", required = true,
        description = "where to save the PKCS#12 keystore")
    @Completion(FilePathCompleter.class)
    private String p12OutputFile;

    @Option(names = "--password", description = "password of the PKCS#12 file")
    private String passwordHint;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) {
      return new EnrollCertRequest.Entry(id, profile, certRequest, null, true, false);
    }

    @Override
    protected EnrollCertRequest.EnrollType getCmpReqType() throws Exception {
      if ("cr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CERT_REQ;
      } else if ("ir".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.INIT_REQ;
      } else {
        throw new IOException("invalid cmpreq-type " + cmpreqType);
      }
    }

    @Override
    public void run() {
      try {
        EnrollCertResult result = enroll();
        EnrollCertResult.CertifiedKeyPairOrError certOrError = firstEnrollResult(result);
        if (certOrError == null) {
          throw new IOException("error, received neither certificate nor error");
        } else if (certOrError.error() != null) {
          throw new IOException(certOrError.error().toString());
        }

        X509Cert cert = certOrError.certificate();
        PrivateKeyInfo privateKeyInfo = certOrError.privateKeyInfo();
        if (cert == null) {
          throw new IOException("no certificate received from the server");
        }
        if (privateKeyInfo == null) {
          throw new IOException("no private key received from the server");
        }

        if (StringUtil.isNotBlank(certOutputFile)) {
          saveVerbose("saved certificate to file", certOutputFile,
              encodeCert(cert.getEncoded(), certOutform));
        }

        X509Cert[] caCertChain = result.caCertChain();
        int size = caCertChain == null ? 1 : 1 + caCertChain.length;
        Certificate[] certchain = new Certificate[size];
        certchain[0] = cert.getCert();
        if (size > 1) {
          for (int i = 0; i < caCertChain.length; i++) {
            certchain[i + 1] = caCertChain[i].getCert();
          }
        }

        char[] pwd = getPassword();
        PKCS12KeyStore ks = KeyUtil.loadPKCS12KeyStore(null, pwd);
        ks.setKeyEntry("main", privateKeyInfo, certchain);
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
          ks.store(bout, pwd);
          saveVerbose("saved key to file", p12OutputFile, bout.toByteArray());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private char[] getPassword() throws Exception {
      return passwordHint == null ? readPassword("Enter PKCS#12 password")
          : Passwords.resolvePassword(passwordHint);
    }
  }

  @Command(name = "cmp-enroll-p11", description = "enroll certificate (PKCS#11 token)",
      mixinStandardHelpOptions = true)
  static class CmpEnrollP11Command extends SignerEnrollCommand {

    @Option(names = "--slot", required = true, description = "slot index")
    private String slotIndex = "0";

    @Option(names = "--key-id", description = "id of the private key in the PKCS#11 device")
    private String keyId;

    @Option(names = "--key-label", description = "label of the private key in the PKCS#11 device")
    private String keyLabel;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(ClientCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      byte[] keyIdBytes = keyId == null ? null : Hex.decode(keyId);
      SignerConf signerConf = getPkcs11SignerConf(
          moduleName, Integer.parseInt(slotIndex), keyLabel, keyIdBytes, getSignAlgoMode());
      return PkiClientRuntime.getSecurities()
          .securityFactory().createSigner("PKCS11", signerConf, (X509Cert[]) null);
    }
  }

  @Command(name = "cmp-enroll-p12", description = "enroll certificate (PKCS#12 keystore)",
      mixinStandardHelpOptions = true)
  static class CmpEnrollP12Command extends SignerEnrollCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 keystore file")
    private String passwordHint;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      char[] password = passwordHint == null
          ? readPassword("Enter keystore password")
          : Passwords.resolvePassword(passwordHint);
      SignerConf signerConf = new SignerConf()
          .setPassword(new String(password)).setParallelism(1).setKeystore("file:" + p12File);
      SignAlgoMode mode = getSignAlgoMode();
      if (mode != null) {
        signerConf.setMode(mode);
      }
      return PkiClientRuntime.getSecurities()
          .securityFactory().createSigner("PKCS12", signerConf, (X509Cert[]) null);
    }
  }

  @Command(name = "cmp-update-serverkeygen",
      description = "update certificate (keypair will be generated by the CA)",
      mixinStandardHelpOptions = true)
  static class CmpUpdateServerkeygenCommand extends UpdateCommand {

    @Option(names = "--cert-outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String certOutform = "der";

    @Option(names = "--cert-out", description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String certOutputFile;

    @Option(names = "--p12-out", required = true,
        description = "where to save the PKCS#12 keystore")
    @Completion(FilePathCompleter.class)
    private String p12OutputFile;

    @Option(names = "--password", description = "password of the PKCS#12 file")
    private String passwordHint;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() {
      return null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) {
      return new EnrollCertRequest.Entry(id, profile, certRequest, null, true, true);
    }

    @Override
    public void run() {
      try {
        EnrollCertResult result = enroll();
        EnrollCertResult.CertifiedKeyPairOrError certOrError = firstEnrollResult(result);
        X509Cert cert = certOrError == null ? null : certOrError.certificate();
        PrivateKeyInfo privateKeyInfo = certOrError == null ? null : certOrError.privateKeyInfo();
        if (cert == null) {
          throw new IOException("no certificate received from the server");
        }
        if (privateKeyInfo == null) {
          throw new IOException("no private key received from the server");
        }

        if (StringUtil.isNotBlank(certOutputFile)) {
          saveVerbose("saved certificate to file", certOutputFile,
              encodeCert(cert.getEncoded(), certOutform));
        }

        char[] pwd = getPassword();
        PKCS12KeyStore ks = KeyUtil.loadPKCS12KeyStore(null, pwd);
        ks.setKeyEntry("main", privateKeyInfo, cert.getCert());
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
          ks.store(bout, pwd);
          saveVerbose("saved key to file", p12OutputFile, bout.toByteArray());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private char[] getPassword() throws Exception {
      return passwordHint == null ? readPassword("Enter PKCS#12 password")
          : Passwords.resolvePassword(passwordHint);
    }
  }

  @Command(name = "cmp-update-p11", description = "update certificate (PKCS#11 token)",
      mixinStandardHelpOptions = true)
  static class CmpUpdateP11Command extends UpdateCertCommand {

    @Option(names = "--slot", required = true, description = "slot index")
    private String slotIndex = "0";

    @Option(names = "--key-id", description = "id of the private key in the PKCS#11 device")
    private String keyId;

    @Option(names = "--key-label", description = "label of the private key in the PKCS#11 device")
    private String keyLabel;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(ClientCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      byte[] keyIdBytes = keyId == null ? null : Hex.decode(keyId);
      SignerConf signerConf = getPkcs11SignerConf(
          moduleName, Integer.parseInt(slotIndex), keyLabel, keyIdBytes, getSignAlgoMode());
      return PkiClientRuntime.getSecurities()
          .securityFactory().createSigner("PKCS11", signerConf, (X509Cert[]) null);
    }
  }

  @Command(name = "cmp-update-p12", description = "update certificate (PKCS#12 keystore)",
      mixinStandardHelpOptions = true)
  static class CmpUpdateP12Command extends UpdateCertCommand {

    @Option(names = "--p12", required = true, description = "PKCS#12 keystore file")
    @Completion(FilePathCompleter.class)
    private String p12File;

    @Option(names = "--password", description = "password of the PKCS#12 keystore file")
    private String passwordHint;

    @Override
    protected ConcurrentSigner getSigner() throws Exception {
      char[] password = passwordHint == null
          ? readPassword("Enter keystore password")
          : Passwords.resolvePassword(passwordHint);
      SignerConf signerConf = new SignerConf()
          .setPassword(new String(password)).setParallelism(1).setKeystore("file:" + p12File);
      SignAlgoMode mode = getSignAlgoMode();
      if (mode != null) {
        signerConf.setMode(mode);
      }
      return PkiClientRuntime.getSecurities()
          .securityFactory().createSigner("PKCS12", signerConf, (X509Cert[]) null);
    }
  }

  abstract static class CmpClientCommand extends ShellBaseCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    protected String caName;

    @Option(names = "--req-out", description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private String reqout;

    @Option(names = "--resp-out", description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String respout;

    protected CmpClient client() throws Exception {
      return PkiClientRuntime.get();
    }

    protected ReqRespDebug getReqRespDebug() {
      boolean saveReq = StringUtil.isNotBlank(reqout);
      boolean saveResp = StringUtil.isNotBlank(respout);
      return saveReq || saveResp ? new ReqRespDebug(saveReq, saveResp) : null;
    }

    protected void saveRequestResponse(ReqRespDebug debug) {
      boolean saveReq = StringUtil.isNotBlank(reqout);
      boolean saveResp = StringUtil.isNotBlank(respout);
      if ((!saveReq && !saveResp) || debug == null || debug.size() == 0) {
        return;
      }

      int n = debug.size();
      for (int i = 0; i < n; i++) {
        ReqRespDebug.ReqRespPair reqResp = debug.get(i);
        if (saveReq && reqResp.request() != null) {
          saveQuiet(n == 1 ? reqout : appendIndex(reqout, i), reqResp.request());
        }
        if (saveResp && reqResp.response() != null) {
          saveQuiet(n == 1 ? respout : appendIndex(respout, i), reqResp.response());
        }
      }
    }

    private static String appendIndex(String filename, int index) {
      int idx = filename.lastIndexOf('.');
      if (idx == -1 || idx == filename.length() - 1) {
        return filename + "-" + index;
      }
      return new StringBuilder(filename).insert(idx, index).insert(idx, '-').toString();
    }

    private static void saveQuiet(String file, byte[] bytes) {
      try {
        IoUtil.save(file, bytes);
      } catch (IOException ex) {
        System.err.println("IOException: " + ex.getMessage());
      }
    }
  }

  abstract static class UpdateCommand extends AuthCmpClientCommand {

    @Option(names = {"--subject", "-s"}, description = "subject to be requested")
    private String subject;

    @Option(names = "--not-before", description = "notBefore yyyyMMddHHmmss UTC")
    private String notBeforeS;

    @Option(names = "--not-after", description = "notAfter yyyyMMddHHmmss UTC")
    private String notAfterS;

    @Option(names = "--oldcert", required = true, description = "old certificate file")
    @Completion(FilePathCompleter.class)
    private String oldCertFile;

    protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

    protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) throws Exception;

    protected EnrollCertResult enroll() throws Exception {
      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      if (subject != null) {
        certTemplateBuilder.setSubject(new X500Name(subject));
      }

      SubjectPublicKeyInfo publicKey = getPublicKey();
      if (publicKey != null) {
        certTemplateBuilder.setPublicKey(publicKey);
      }

      if (StringUtil.isNotBlank(notBeforeS) || StringUtil.isNotBlank(notAfterS)) {
        Time notBefore = StringUtil.isNotBlank(notBeforeS)
            ? new Time(Date.from(DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS))) : null;
        Time notAfter = StringUtil.isNotBlank(notAfterS)
            ? new Time(Date.from(DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS))) : null;
        certTemplateBuilder.setValidity(new OptionalValidity(notBefore, notAfter));
      }

      X509Cert oldCert = X509Util.parseCert(new File(oldCertFile));
      CertId oldCertId = new CertId(new GeneralName(oldCert.issuer()), oldCert.serialNumber());
      Controls controls = new Controls(
          new AttributeTypeAndValue(OIDs.CMP.regCtrl_oldCertID, oldCertId));
      CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), controls);

      EnrollCertRequest.Entry reqEntry = buildEnrollCertRequestEntry("id-1", null, certReq);
      EnrollCertRequest request = new EnrollCertRequest(EnrollCertRequest.EnrollType.KEY_UPDATE);
      request.addRequestEntry(reqEntry);

      ReqRespDebug debug = getReqRespDebug();
      try {
        return client().enrollCerts(caName, getRequestor(), request, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }
  }

  abstract static class UpdateCertCommand extends UpdateCommand {

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    @Option(names = "--embeds-publickey",
        description = "whether to embed the public key in the request")
    private Boolean embedsPublicKey = Boolean.FALSE;

    protected SignAlgoMode getSignAlgoMode() {
      return Boolean.TRUE.equals(rsaPss) ? SignAlgoMode.RSAPSS : null;
    }

    protected abstract ConcurrentSigner getSigner() throws Exception;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      return Boolean.TRUE.equals(embedsPublicKey)
          ? getSigner().x509Cert().subjectPublicKeyInfo() : null;
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) throws Exception {
      ConcurrentSigner signer = getSigner();
      ProofOfPossessionSigningKeyBuilder popBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      Signer signer0 = signer.borrowSigner();
      POPOSigningKey popSk;
      try {
        popSk = popBuilder.build(signer0.x509Signer());
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession pop = new ProofOfPossession(popSk);
      return new EnrollCertRequest.Entry(id, profile, certRequest, pop, false, true);
    }

    @Override
    public void run() {
      try {
        EnrollCertResult result = enroll();
        EnrollCertResult.CertifiedKeyPairOrError certOrError = firstEnrollResult(result);
        X509Cert cert = certOrError == null ? null : certOrError.certificate();
        if (cert == null) {
          throw new IOException("no certificate received from the server");
        }

        saveVerbose("saved certificate to file", outputFile,
            encodeCert(cert.getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  abstract static class UnRevokeCertCommand extends AuthCmpClientCommand {

    @Option(names = "--ca-cert", required = true, description = "CA certificate file")
    @Completion(FilePathCompleter.class)
    private String caCertFile;

    @Option(names = {"--cert", "-c"}, split = ",",
        description = "certificate files (either cert or serial is allowed)")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Option(names = {"--serial", "-s"}, split = ",",
        description = "serial numbers (either cert or serial is allowed)")
    private List<String> serialNumbersS;

    protected X509Cert getCaCert() throws Exception {
      return X509Util.parseCert(new File(caCertFile));
    }

    protected ReqInfo getReqInfo() throws Exception {
      if (CollectionUtil.isEmpty(certFiles) && CollectionUtil.isEmpty(serialNumbersS)) {
        throw new IllegalArgumentException("none of cert and serial is specified");
      }

      List<String> ids = new LinkedList<>();
      List<String> sources = new LinkedList<>();
      List<BigInteger> serialNumbers = new LinkedList<>();

      X509Cert caCert = getCaCert();
      int id = 1;
      if (CollectionUtil.isNotEmpty(certFiles)) {
        for (String certFile : certFiles) {
          X509Cert cert = X509Util.parseCert(new File(certFile));
          assertIssuedByCa(cert, caCert, certFile);
          ids.add(Integer.toString(id++));
          sources.add(certFile);
          serialNumbers.add(cert.serialNumber());
        }
      }

      if (CollectionUtil.isNotEmpty(serialNumbersS)) {
        for (String serialNumber : serialNumbersS) {
          ids.add(Integer.toString(id++));
          sources.add(serialNumber);
          serialNumbers.add(toBigInt(serialNumber));
        }
      }

      ReqInfo reqInfo = new ReqInfo();
      reqInfo.caCert = caCert;
      reqInfo.ids = ids;
      reqInfo.sources = sources;
      reqInfo.serialNumbers = serialNumbers;
      return reqInfo;
    }

    protected void analyseResult(boolean revoke, Map<String, CertIdOrError> certIdOrErrors,
                                 ReqInfo reqInfo) throws IOException {
      boolean failed = false;
      List<Integer> processedIndex = new ArrayList<>(reqInfo.sources.size());
      for (Map.Entry<String, CertIdOrError> certIdOrError : certIdOrErrors.entrySet()) {
        String id = certIdOrError.getKey();
        int index = reqInfo.ids.indexOf(id);
        if (index == -1) {
          failed = true;
          println("error in CMP protocol, unknown id " + id);
          continue;
        }

        processedIndex.add(index);
        String source = reqInfo.sources.get(index);
        if (certIdOrError.getValue().error() != null) {
          failed = true;
          PkiStatusInfo error = certIdOrError.getValue().error();
          println((revoke ? "revoking" : "unsuspending")
              + " certificate " + source + " failed: " + error);
        } else {
          println((revoke ? "revoked" : "unsuspended") + " certificate " + source);
        }
      }

      if (reqInfo.sources.size() != processedIndex.size()) {
        processedIndex.sort(Collections.reverseOrder());
        for (Integer index : processedIndex) {
          reqInfo.sources.remove((int) index);
        }
        failed = true;
        println("server did not process request for " + reqInfo.sources);
      }

      if (failed) {
        throw new IOException("failed processing at least one certificate");
      }
    }
  }

  abstract static class AbstractEnrollCommand extends AuthCmpClientCommand {

    @Option(names = {"--subject", "-s"}, required = true, description = "subject to be requested")
    private String subject;

    @Option(names = {"--profile", "-p"}, required = true, description = "certificate profile")
    private String profile;

    @Option(names = "--not-before", description = "notBefore yyyyMMddHHmmss UTC")
    private String notBeforeS;

    @Option(names = "--not-after", description = "notAfter yyyyMMddHHmmss UTC")
    private String notAfterS;

    protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

    protected abstract EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) throws Exception;

    protected abstract EnrollCertRequest.EnrollType getCmpReqType() throws Exception;

    protected EnrollCertResult enroll() throws Exception {
      CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();
      certTemplateBuilder.setSubject(new X500Name(subject));

      SubjectPublicKeyInfo publicKey = getPublicKey();
      if (publicKey != null) {
        certTemplateBuilder.setPublicKey(publicKey);
      }

      if (StringUtil.isNotBlank(notBeforeS) || StringUtil.isNotBlank(notAfterS)) {
        Time notBefore = StringUtil.isNotBlank(notBeforeS)
            ? new Time(Date.from(DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS))) : null;
        Time notAfter = StringUtil.isNotBlank(notAfterS)
            ? new Time(Date.from(DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS))) : null;
        certTemplateBuilder.setValidity(new OptionalValidity(notBefore, notAfter));
      }

      CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), null);
      EnrollCertRequest.Entry reqEntry = buildEnrollCertRequestEntry("id-1", profile, certReq);
      EnrollCertRequest request = new EnrollCertRequest(getCmpReqType());
      request.addRequestEntry(reqEntry);

      ReqRespDebug debug = getReqRespDebug();
      try {
        return client().enrollCerts(caName, getRequestor(), request, debug);
      } finally {
        saveRequestResponse(debug);
      }
    }
  }

  abstract static class SignerEnrollCommand extends AbstractEnrollCommand {

    @Option(names = "--cmpreq-type", description = "CMP request type: ir, cr, or ccr")
    @Completion(values = {"ir", "cr", "ccr"})
    private String cmpreqType = "cr";

    @Option(names = "--outform", description = "output format of the certificate")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "where to save the certificate")
    @Completion(FilePathCompleter.class)
    private String outputFile;

    @Option(names = "--rsa-pss", description = "whether to use RSAPSS for POP")
    private Boolean rsaPss = Boolean.FALSE;

    protected SignAlgoMode getSignAlgoMode() {
      return Boolean.TRUE.equals(rsaPss) ? SignAlgoMode.RSAPSS : null;
    }

    protected abstract ConcurrentSigner getSigner() throws Exception;

    @Override
    protected SubjectPublicKeyInfo getPublicKey() throws Exception {
      ConcurrentSigner signer = getSigner();
      X509Cert cert = signer.x509Cert();
      if (cert != null) {
        return cert.subjectPublicKeyInfo();
      }

      PublicKey publicKey = signer.publicKey();
      if (publicKey != null) {
        return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      }

      throw new IOException("could not extract public key");
    }

    @Override
    protected EnrollCertRequest.Entry buildEnrollCertRequestEntry(
        String id, String profile, CertRequest certRequest) throws Exception {
      ConcurrentSigner signer = getSigner();
      ProofOfPossessionSigningKeyBuilder popBuilder =
          new ProofOfPossessionSigningKeyBuilder(certRequest);
      Signer signer0 = signer.borrowSigner();
      POPOSigningKey popSk;
      try {
        popSk = popBuilder.build(signer0.x509Signer());
      } finally {
        signer.requiteSigner(signer0);
      }

      ProofOfPossession pop = new ProofOfPossession(popSk);
      return new EnrollCertRequest.Entry(id, profile, certRequest, pop);
    }

    @Override
    protected EnrollCertRequest.EnrollType getCmpReqType() throws Exception {
      if ("cr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CERT_REQ;
      } else if ("ir".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.INIT_REQ;
      } else if ("ccr".equalsIgnoreCase(cmpreqType)) {
        return EnrollCertRequest.EnrollType.CROSS_CERT_REQ;
      } else {
        throw new IOException("invalid cmpreq-type " + cmpreqType);
      }
    }

    @Override
    public void run() {
      try {
        EnrollCertResult result = enroll();
        EnrollCertResult.CertifiedKeyPairOrError certOrError = firstEnrollResult(result);
        if (certOrError == null) {
          throw new IOException("error, received neither certificate nor error");
        } else if (certOrError.error() != null) {
          throw new IOException(certOrError.error().toString());
        }

        saveVerbose("saved certificate to file", outputFile,
            encodeCert(certOrError.certificate().getEncoded(), outform));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  private static class ReqInfo {
    private X509Cert caCert;
    private List<String> ids;
    private List<BigInteger> serialNumbers;
    private List<String> sources;
  }

  static EnrollCertResult.CertifiedKeyPairOrError firstEnrollResult(EnrollCertResult result) {
    if (result == null || result.allIds().isEmpty()) {
      return null;
    }
    String id = result.allIds().iterator().next();
    return result.getCertOrError(id);
  }

  static void assertIssuedByCa(X509Cert cert, X509Cert ca, String certDesc)
      throws IOException {
    if (!X509Util.issues(ca, cert)) {
      throw new IOException("certificate " + certDesc + " is not issued by the CA");
    }
  }

  static SignerConf getPkcs11SignerConf(
      String pkcs11ModuleName, int slotIndex, String keyLabel, byte[] keyId, SignAlgoMode mode) {
    if (keyId == null && keyLabel == null) {
      throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
    }

    SignerConf conf = new SignerConf();
    conf.setParallelism(1);
    if (StringUtil.isNotBlank(pkcs11ModuleName)) {
      conf.setModule(pkcs11ModuleName);
    }
    conf.setSlot(slotIndex);
    if (keyId != null) {
      conf.setKeyId(keyId);
    }
    if (keyLabel != null) {
      conf.setKeyLabel(keyLabel);
    }
    if (mode != null) {
      conf.setMode(mode);
    }
    return conf;
  }

}
