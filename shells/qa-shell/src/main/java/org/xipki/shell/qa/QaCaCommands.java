// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.CaEnrollBenchEntry;
import org.xipki.qa.ca.CaEnrollBenchEntry.RandomDn;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchmark;
import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ca.CertprofileQa;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.ca.mgmt.CaCompleters;
import org.xipki.shell.ca.mgmt.CaMgmtRuntime;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.security.SecurityCompleters;
import org.xipki.shell.xi.Completers;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.rmi.UnexpectedException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The QA shell.
 *
 * @author Lijun Liao (xipki)
 */

class QaCaCommands {

  abstract static class QaCommand extends ShellBaseCommand {
    protected CaQaSystemManager qaManager() {
      return QaRuntime.getCaQaManager();
    }
  }

  abstract static class QaMgmtCommand extends ShellBaseCommand {
    protected CaMgmtClient client() throws Exception {
      return CaMgmtRuntime.get();
    }
  }

  @Command(name = "init-caqa", description = "initialize the CA QA manager",
      mixinStandardHelpOptions = true)
  static class InitCaQaCommand extends QaCommand {

    @Override
    public void run() {
      boolean initialized = qaManager().init();
      println(initialized
          ? "CA QA system initialized successfully" : "CA QA system initialization failed");
    }
  }

  @Command(name = "check-cert", description = "check the certificate",
      mixinStandardHelpOptions = true)
  static class CheckCertCommand extends QaCommand {

    @Option(names = {"--cert", "-c"}, required = true, description = "certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--issuer", description = "issuer name")
    @Completion(QaCompleters.IssuerNameCompleter.class)
    private String issuerName;

    @Option(names = "--csr", required = true, description = "CSR file")
    @Completion(FilePathCompleter.class)
    private String csrFile;

    @Option(names = {"--profile", "-p"}, required = true, description = "certificate profile")
    @Completion(QaCompleters.ProfileNameCompleter.class)
    private String profileName;

    @Option(names = {"--verbose", "-v"}, description = "show status verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        CaQaSystemManager qaManager = qaManager();
        Set<String> issuerNames = qaManager.getIssuerNames();
        if (issuerNames.isEmpty()) {
          throw new IllegalArgumentException("no issuer is configured");
        }

        String effectiveIssuer = issuerName;
        if (effectiveIssuer == null) {
          if (issuerNames.size() != 1) {
            throw new IllegalArgumentException("no issuer is specified");
          }
          effectiveIssuer = issuerNames.iterator().next();
        }
        if (!issuerNames.contains(effectiveIssuer)) {
          throw new IllegalArgumentException("issuer " + effectiveIssuer
              + " is not within the configured issuers " + issuerNames);
        }

        IssuerInfo issuerInfo = qaManager.getIssuer(effectiveIssuer);
        CertprofileQa qa = Optional.ofNullable(qaManager.getCertprofile(profileName))
            .orElseThrow(() -> new IllegalArgumentException(
                "found no certificate profile named '" + profileName + "'"));

        CertificationRequest csr = X509Util.parseCsr(new File(csrFile));
        CertificationRequestInfo reqInfo = csr.getCertificationRequestInfo();
        Extensions extensions = extractExtensions(reqInfo.getAttributes());

        byte[] certBytes = IoUtil.read(certFile);
        ValidationResult result = qa.checkCert(certBytes, issuerInfo,
            reqInfo.getSubject(), reqInfo.getSubjectPublicKeyInfo(), extensions);

        StringBuilder sb = new StringBuilder();
        sb.append(certFile).append(" (certprofile ").append(profileName).append(")\n");
        sb.append("\tcertificate is ").append(result.isAllSuccessful() ? "valid" : "invalid");
        for (ValidationIssue issue : result.getValidationIssues()) {
          if (verbose || issue.isFailed()) {
            sb.append("\n");
            format(issue, "    ", sb);
          }
        }

        println(sb.toString());
        if (!result.isAllSuccessful()) {
          throw new RuntimeException("certificate is invalid");
        }
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check certificate: " + ex.getMessage(), ex);
      }
    }

    private static Extensions extractExtensions(ASN1Set attrs) {
      Args.notNull(attrs, "attrs");
      for (int i = 0; i < attrs.size(); i++) {
        Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
        if (OIDs.PKCS9.pkcs9_at_extensionRequest.equals(attr.getAttrType())) {
          return Extensions.getInstance(attr.getAttributeValues()[0]);
        }
      }
      return null;
    }

    private static void format(ValidationIssue issue, String prefix, StringBuilder sb) {
      sb.append(prefix).append(issue.getCode())
          .append(", ").append(issue.getDescription())
          .append(", ").append(issue.isFailed() ? "failed" : "successful");
      if (issue.getFailureMessage() != null) {
        sb.append(", ").append(issue.getFailureMessage());
      }
    }
  }

  @Command(name = "caalias-check", description = "check CA aliases (QA)",
      mixinStandardHelpOptions = true)
  static class CaAliasCheckCommand extends QaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--alias", required = true, description = "alias name")
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String aliasName;

    @Override
    public void run() {
      try {
        println("checking CA alias='" + aliasName + "', CA='" + caName + "'");
        String actualCa = Optional.ofNullable(client().getCaNameForAlias(aliasName))
            .orElseThrow(() -> new RuntimeException("alias '" + aliasName + "' is not configured"));
        assertEquals("CA name", caName, actualCa);
        println(" checked CA alias='" + aliasName + "', CA='" + caName + "'");
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check CA alias: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-check", description = "check information of CAs (QA)",
      mixinStandardHelpOptions = true)
  static class CaCheckCommand extends QaMgmtCommand {

    @Option(names = "--name", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--sn-len", description = "serial number length")
    private Integer snLen;

    @Option(names = "--status", description = "CA status")
    @Completion(Completers.StatusCompleter.class)
    private String caStatus;

    @Option(names = "--ca-cert-uri", description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(names = "--ocsp-uri", description = "OCSP URI or null")
    private List<String> ocspUris;

    @Option(names = "--crl-uri", description = "CRL URI or null")
    private List<String> crlUris;

    @Option(names = "--deltacrl-uri", description = "delta CRL URI or null")
    private List<String> deltaCrlUris;

    @Option(names = "--permission", description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private List<String> permissions;

    @Option(names = "--max-validity", description = "maximal validity")
    private String maxValidity;

    @Option(names = "--expiration-period", description = "expiration period")
    private Integer expirationPeriod;

    @Option(names = "--keep-expired-certs", description = "keep expired certs")
    private Integer keepExpiredCertDays;

    @Option(names = "--crl-signer", description = "CRL signer name or null")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String crlSignerName;

    @Option(names = "--keypair-gen", description = "keypair generation names or null")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private List<String> keypairGenNames;

    @Option(names = "--crl-control", description = "CRL control or null")
    private String crlControl;

    @Option(names = "--num-crls", description = "number of CRLs")
    private Integer numCrls;

    @Option(names = "--cert", description = "CA certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--certchain", description = "certificate chain files")
    @Completion(FilePathCompleter.class)
    private List<String> issuerCertFiles;

    @Option(names = "--signer-type", description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(names = "--signer-conf", description = "CA signer configuration or null")
    private String signerConf;

    @Option(names = "--validity-mode", description = "validity mode")
    private String validityModeS;

    @Option(names = "--extra-control", description = "extra control")
    private String extraControl;

    @Override
    public void run() {
      try {
        ChangeCaEntry expected = getChangeCaEntry();
        String name = expected.ident().name();
        println("checking CA " + name);

        CaEntry actual = Optional.ofNullable(client().getCa(name))
            .orElseThrow(() -> new RuntimeException("could not find CA '" + name + "'"));

        if (expected.caUris() != null) {
          assertObjEquals("CA URIs", expected.caUris(), actual.base().caUris());
        }
        if (expected.encodedCert() != null
            && !certEquals(expected.encodedCert(), actual.cert().getEncoded())) {
          throw new RuntimeException("CA cert is not as expected");
        }
        if (expected.encodedCertchain() != null) {
          List<byte[]> expChain = expected.encodedCertchain();
          List<X509Cert> actChain = actual.certchain();
          int expSize = expChain == null ? 0 : expChain.size();
          int actSize = actChain == null ? 0 : actChain.size();
          if (expSize != actSize) {
            if (actChain != null && !actChain.isEmpty()) {
              throw new RuntimeException("Length of CA certchain " + actSize
                  + " is not as expected " + expSize);
            }
          } else {
            for (int i = 0; i < expSize; i++) {
              if (!certEquals(expChain.get(i), actChain.get(i).getEncoded())) {
                throw new RuntimeException("CA cert chain[" + i + "] is not as expected");
              }
            }
          }
        }

        if (expected.serialNoLen() != null) {
          assertObjEquals("serial number length", expected.serialNoLen(), actual.base().snSize());
        }
        if (expected.crlControl() != null) {
          assertObjEquals("CRL control", new CrlControl(expected.crlControl()),
              actual.base().crlControl());
        }
        if (expected.crlSignerName() != null) {
          assertEquals("CRL signer name", expected.crlSignerName(), actual.base().crlSignerName());
        }
        if (expected.expirationPeriod() != null) {
          assertObjEquals("Expiration period", expected.expirationPeriod(),
              actual.base().expirationPeriod());
        }
        if (expected.extraControl() != null) {
          assertObjEquals("Extra control", expected.extraControl(), actual.base().extraControl());
        }
        if (expected.maxValidity() != null) {
          assertObjEquals("Max validity", expected.maxValidity(), actual.base().maxValidity());
        }
        if (expected.keepExpiredCertDays() != null) {
          assertObjEquals("keepExpiredCertDays", expected.keepExpiredCertDays(),
              actual.base().keepExpiredCertDays());
        }
        if (expected.numCrls() != null) {
          assertObjEquals("num CRLs", expected.numCrls(), actual.base().numCrls());
        }
        if (expected.permissions() != null) {
          assertObjEquals("permissions", new Permissions(expected.permissions()),
              actual.base().permissions());
        }
        if (expected.signerType() != null) {
          assertTypeEquals("signer type", expected.signerType(), actual.base().signerType());
        }
        if (expected.signerConf() != null) {
          ConfPairs exp = new ConfPairs(expected.signerConf());
          exp.removePair("keystore");
          ConfPairs got = new ConfPairs(actual.signerConf());
          got.removePair("keystore");
          assertObjEquals("signer conf", exp, got);
        }
        if (expected.status() != null) {
          assertObjEquals("status", expected.status(), actual.base().status());
        }
        if (expected.validityMode() != null) {
          assertObjEquals("validity mode", expected.validityMode(), actual.base().validityMode());
        }

        println(" checked CA" + name);
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check CA: " + ex.getMessage(), ex);
      }
    }

    private ChangeCaEntry getChangeCaEntry() throws Exception {
      ChangeCaEntry entry = new ChangeCaEntry(new NameId(null, caName));
      if (snLen != null) {
        entry.setSerialNoLen(snLen);
      }
      if (caStatus != null) {
        entry.setStatus(CaStatus.forName(caStatus));
      }
      if (expirationPeriod != null) {
        entry.setExpirationPeriod(expirationPeriod);
      }
      if (keepExpiredCertDays != null) {
        entry.setKeepExpiredCertDays(keepExpiredCertDays);
      }
      if (certFile != null) {
        entry.setEncodedCert(IoUtil.read(certFile));
      }
      if (issuerCertFiles != null && !issuerCertFiles.isEmpty()) {
        List<byte[]> list = new ArrayList<>(issuerCertFiles.size());
        for (String file : issuerCertFiles) {
          if (CaManager.NULL.equalsIgnoreCase(file)) {
            list.clear();
            break;
          }
          list.add(X509Util.parseCert(new File(file)).getEncoded());
        }
        entry.setEncodedCertchain(list);
      }
      if (signerType != null) {
        entry.setSignerType(signerType);
      }
      if (signerConf != null) {
        entry.setSignerConf(signerConf);
      }
      if (permissions != null && !permissions.isEmpty()) {
        entry.setPermissions(permissions);
      }
      entry.setCaUris(new CaUris(getUris(caCertUris), getUris(ocspUris),
          getUris(crlUris), getUris(deltaCrlUris)));
      if (validityModeS != null) {
        entry.setValidityMode(ValidityMode.forName(validityModeS));
      }
      if (maxValidity != null) {
        entry.setMaxValidity(Validity.getInstance(maxValidity));
      }
      if (crlControl != null) {
        entry.setCrlControl(crlControl);
      }
      if (crlSignerName != null) {
        entry.setCrlSignerName(crlSignerName);
      }
      if (keypairGenNames != null && !keypairGenNames.isEmpty()) {
        if (CaManager.NULL.equalsIgnoreCase(keypairGenNames.get(0))) {
          keypairGenNames.clear();
        }
        entry.setKeypairGenNames(keypairGenNames);
      }
      if (extraControl != null) {
        entry.setExtraControl(new ConfPairs(extraControl).getEncoded());
      }
      if (numCrls != null) {
        entry.setNumCrls(numCrls);
      }
      return entry;
    }
  }

  @Command(name = "caprofile-check", description = "check certificate profiles in a CA (QA)",
      mixinStandardHelpOptions = true)
  static class CaProfileCheckCommand extends QaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--profile", required = true,
        description = "profile name and aliases, <name>[:<comma-separated aliases>]")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String profileNameAliases;

    @Override
    public void run() {
      try {
        println("checking CA profile CA='" + caName + "', profile='" + profileNameAliases + "'");
        if (client().getCa(caName) == null) {
          throw new RuntimeException("could not find CA '" + caName + "'");
        }

        CaProfileEntry expected = CaProfileEntry.decode(profileNameAliases);
        Set<CaProfileEntry> entries = client().getCertprofilesForCa(caName);
        CaProfileEntry actual = null;
        for (CaProfileEntry entry : entries) {
          if (entry.profileName().equals(expected.profileName())) {
            actual = entry;
            break;
          }
        }

        if (actual == null) {
          throw new RuntimeException("CA is not associated with profile '"
              + expected.profileName() + "'");
        }
        if (!expected.equals(actual)) {
          throw new RuntimeException("CA-Profile unmatch, expected=" + expected
              + ", but received=" + actual);
        }
        println(" checked CA profile CA='" + caName + "', profile='" + profileNameAliases + "'");
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check CA profile: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "capub-check", description = "check publishers in a CA (QA)",
      mixinStandardHelpOptions = true)
  static class CaPublisherCheckCommand extends QaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--publisher", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String publisherName;

    @Override
    public void run() {
      try {
        println("checking CA publisher CA='" + caName + "', publisher='" + publisherName + "'");
        if (client().getCa(caName) == null) {
          throw new RuntimeException("could not find CA '" + caName + "'");
        }

        Set<String> entries = client().getPublisherNamesForCa(caName);
        String expected = publisherName.toLowerCase();
        for (String entry : entries) {
          if (entry.equals(expected)) {
            println(" checked CA publisher CA='" + caName + "', publisher='" + publisherName + "'");
            return;
          }
        }

        throw new RuntimeException("CA is not associated with publisher '" + publisherName + "'");
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check CA publisher: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "careq-check", description = "check requestors in a CA (QA)",
      mixinStandardHelpOptions = true)
  static class CaRequestorCheckCommand extends QaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(names = "--permission", description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(names = "--profile", description = "profile name, all, or null")
    @Completion(QaCompleters.ProfileNameCompleter.class)
    private Set<String> profiles;

    @Override
    public void run() {
      try {
        println("checking CA requestor CA='" + caName + "', requestor='" + requestorName + "'");
        if (client().getCa(caName) == null) {
          throw new UnexpectedException("could not find CA '" + caName + "'");
        }

        Set<CaHasRequestorEntry> entries = client().getRequestorsForCa(caName);
        CaHasRequestorEntry actual = null;
        String expectedRequestor = requestorName.toLowerCase();
        for (CaHasRequestorEntry entry : entries) {
          if (entry.requestorIdent().name().equals(expectedRequestor)) {
            actual = entry;
            break;
          }
        }

        if (actual == null) {
          throw new RuntimeException("CA is not associated with requestor '" + requestorName + "'");
        }

        if (permissions != null) {
          Permissions expectedPermissions = new Permissions(permissions);
          if (expectedPermissions.value() != actual.permissions().value()) {
            throw new RuntimeException("permissions: is '" + actual.permissions().value()
                + "', but expected '" + expectedPermissions.value() + "'");
          }
        }

        if (profiles != null) {
          Set<String> effectiveProfiles = profiles;
          if (effectiveProfiles.size() == 1
              && "null".equalsIgnoreCase(effectiveProfiles.iterator().next())) {
            effectiveProfiles = Collections.emptySet();
          }
          if (!new ArrayList<>(effectiveProfiles).equals(actual.profiles())) {
            throw new RuntimeException("profiles: is '" + actual.profiles()
                + "', but expected '" + effectiveProfiles + "'");
          }
        }

        println(" checked CA requestor CA='" + caName + "', requestor='" + requestorName + "'");
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check CA requestor: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "profile-check", description = "check information of profiles (QA)",
      mixinStandardHelpOptions = true)
  static class ProfileCheckCommand extends QaMgmtCommand {

    @Option(names = "--name", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    private String type;

    @Option(names = "--conf", description = "profile configuration")
    private String conf;

    @Option(names = "--conf-file", description = "profile configuration file")
    @Completion(FilePathCompleter.class)
    private String confFile;

    @Override
    public void run() {
      try {
        println("checking profile " + name);
        if (type == null && conf == null && confFile == null) {
          println("nothing to update");
          return;
        }

        String effectiveConf = conf;
        if (effectiveConf == null && confFile != null) {
          effectiveConf = StringUtil.toUtf8String(IoUtil.read(confFile));
        }

        CertprofileEntry actual = Optional.ofNullable(client().getCertprofile(name))
            .orElseThrow(() -> new RuntimeException(
                "certificate profile named '" + name + "' is not configured"));

        assertTypeEquals("type", type == null ? "xijson" : type, actual.type());
        assertEquals("conf", effectiveConf, actual.conf());
        println(" checked profile " + name);
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check profile: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "publisher-check", description = "check information of publishers (QA)",
      mixinStandardHelpOptions = true)
  static class PublisherCheckCommand extends QaMgmtCommand {

    @Option(names = "--name", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Option(names = "--type", description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    private String type;

    @Option(names = "--conf", description = "publisher configuration")
    private String conf;

    @Override
    public void run() {
      try {
        println("checking publisher " + name);
        PublisherEntry actual = Optional.ofNullable(client().getPublisher(name))
            .orElseThrow(() -> new RuntimeException(
                "publisher named '" + name + "' is not configured"));

        if (actual.type() != null) {
          assertTypeEquals("type", type, actual.type());
        }
        if (actual.conf() != null) {
          assertEquals("signer conf", conf, actual.conf());
        }
        println(" checked publisher " + name);
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check publisher: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "requestor-check", description = "check information of requestors (QA)",
      mixinStandardHelpOptions = true)
  static class RequestorCheckCommand extends QaMgmtCommand {

    @Option(names = "--name", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(names = "--cert", required = true, description = "requestor certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Override
    public void run() {
      try {
        println("checking requestor " + name);
        RequestorEntry actual = Optional.ofNullable(client().getRequestor(name))
            .orElseThrow(() -> new RuntimeException(
                "requestor named '" + name + "' is not configured"));

        byte[] expectedCert = IoUtil.read(certFile);
        String expectedType = RequestorEntry.TYPE_CERT;
        if (!actual.type().equals(expectedType)) {
          throw new RuntimeException("IdNameTypeConf type is not " + expectedType);
        }

        String conf = Optional.ofNullable(actual.conf())
            .orElseThrow(() -> new RuntimeException(
                "CaCert: is not configured explicitly as expected"));
        if (!certEquals(expectedCert, Base64.decode(conf))) {
          throw new RuntimeException("CaCert: the expected one and the actual one differ");
        }

        println(" checked requestor " + name);
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check requestor: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "signer-check", description = "check information of signer (QA)",
      mixinStandardHelpOptions = true)
  static class SignerCheckCommand extends QaMgmtCommand {

    @Option(names = "--name", required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(names = "--cert", description = "signer certificate file or null")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--conf", description = "signer configuration")
    private String conf;

    @Override
    public void run() {
      try {
        println("checking signer " + name);
        SignerEntry actual = Optional.ofNullable(client().getSigner(name))
            .orElseThrow(() -> new RuntimeException(
                "signer named '" + name + "' is not configured"));

        if (CaManager.NULL.equalsIgnoreCase(certFile)) {
          if (actual.base64Cert() != null) {
            throw new RuntimeException("CaCert: is configured but expected is none");
          }
        } else if (certFile != null) {
          byte[] expected = IoUtil.read(certFile);
          if (actual.base64Cert() == null) {
            throw new RuntimeException("CaCert: is not configured explicitly as expected");
          }
          if (!certEquals(expected, Base64.decode(actual.base64Cert()))) {
            throw new RuntimeException("CaCert: the expected one and the actual one differ");
          }
        }

        String signerConf = conf;
        if (signerConf != null) {
          ConfPairs pairs = new ConfPairs(signerConf);
          String algoName = "algo";
          if (pairs.value(algoName) != null) {
            pairs.putPair(algoName, pairs.value(algoName).toUpperCase(Locale.ROOT));
          }
          signerConf = pairs.getEncoded();
          assertEquals("conf", signerConf, actual.conf());
        }

        println(" checked signer " + name);
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not check signer: " + ex.getMessage(), ex);
      }
    }
  }

  abstract static class AbstractBenchmarkEnrollCommand extends ShellBaseCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(names = {"--profile", "-p"}, required = true,
        description = "certificate profile that allows duplication of public key")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    protected String certprofile;

    @Option(names = {"--subject", "-s"}, required = true, description = "subject template")
    protected String subjectTemplate;

    @Option(names = "--random-dn", description = "DN name to be incremented")
    @Completion(values = {"GIVENNAME", "SURNAME", "STREET", "POSTALCODE", "O", "OU", "CN"})
    protected String randomDnStr = "O";

    @Option(names = "--duration", description = "duration")
    protected String duration = "30s";

    @Option(names = "--thread", description = "number of threads")
    protected Integer numThreads = 5;

    @Option(names = "-n", description = "number of certificates per request")
    protected Integer num = 1;

    @Option(names = "--max-num", description = "maximal number of requests, 0 for unlimited")
    protected Integer maxRequests = 0;

    protected RandomDn randomDn() {
      if (randomDnStr == null) {
        return null;
      }
      RandomDn randomDn = RandomDn.getInstance(randomDnStr);
      if (randomDn == null) {
        throw new IllegalArgumentException("invalid randomDn " + randomDnStr);
      }
      return randomDn;
    }

    protected void checkBenchmarkParameters() {
      if (numThreads == null || numThreads < 1) {
        throw new IllegalArgumentException("invalid number of threads " + numThreads);
      }
    }
  }

  @Command(name = "benchmark-enroll-serverkeygen",
      description = "Enroll certificate (CA generates keypairs, benchmark)",
      mixinStandardHelpOptions = true)
  static class BenchmarkCaGenEnrollCommand extends AbstractBenchmarkEnrollCommand {

    @Override
    public void run() {
      try {
        checkBenchmarkParameters();
        String description = StringUtil.concatObjectsCap(200,
            "subjectTemplate: ", subjectTemplate,
            "\nprofile: ", certprofile, "\nmaxRequests: ", maxRequests);

        CaEnrollBenchEntry benchmarkEntry = new CaEnrollBenchEntry(
            certprofile, null, subjectTemplate, randomDn());
        CaEnrollBenchmark benchmark = new CaEnrollBenchmark(
            caName, benchmarkEntry, maxRequests, num, description);
        benchmark.setDuration(duration).setThreads(numThreads).execute();
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not run enroll-serverkeygen benchmark: "
                + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "benchmark-enroll", description = "Enroll certificate (benchmark)",
      mixinStandardHelpOptions = true)
  static class BenchmarkEnrollCommand extends AbstractBenchmarkEnrollCommand {

    @Option(names = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Option(names = "--new-key", description = "Generate different keypair for each certificate")
    private boolean newKey;

    @Override
    public void run() {
      try {
        checkBenchmarkParameters();
        String description = StringUtil.concatObjectsCap(200,
            "subjectTemplate: ", subjectTemplate, "\nprofile: ", certprofile,
            "\nkeySpec: ", keyspec, "\nmaxRequests: ", maxRequests);

        KeySpec ks = KeySpec.ofKeySpec(keyspec);
        CaEnrollBenchKeyEntry keyEntry = new CaEnrollBenchKeyEntry(
            ks, !newKey, new SecureRandom());
        CaEnrollBenchEntry benchmarkEntry = new CaEnrollBenchEntry(
            certprofile, keyEntry, subjectTemplate, randomDn());
        CaEnrollBenchmark benchmark = new CaEnrollBenchmark(
            caName, benchmarkEntry, maxRequests, num, description);
        benchmark.setDuration(duration).setThreads(numThreads).execute();
      } catch (Exception ex) {
        throw ex instanceof RuntimeException ? (RuntimeException) ex
            : new RuntimeException("could not run enroll benchmark: " + ex.getMessage(), ex);
      }
    }
  }

  private static void assertEquals(String label, String expected, String actual) {
    String effectiveExpected = CaManager.NULL.equals(expected) ? null : expected;
    if (!Objects.equals(effectiveExpected, actual)) {
      throw new RuntimeException(label + ": is '" + actual + "', but expected '" + expected + "'");
    }
  }

  private static void assertTypeEquals(String label, String expected, String actual) {
    String effectiveExpected = CaManager.NULL.equals(expected) ? null : expected;
    boolean equal = effectiveExpected == null ? actual == null
        : effectiveExpected.equalsIgnoreCase(actual);
    if (!equal) {
      throw new RuntimeException(label + ": is '" + actual +
          "', but expected '" + effectiveExpected + "'");
    }
  }

  private static boolean certEquals(byte[] certBytes1, byte[] certBytes2) {
    if (certBytes1 == null && certBytes2 == null) {
      return true;
    } else if (certBytes1 != null && certBytes2 != null) {
      try {
        return Arrays.equals(X509Util.parseCert(certBytes1).getEncoded(),
            X509Util.parseCert(certBytes2).getEncoded());
      } catch (Exception ex) {
        return false;
      }
    } else {
      return false;
    }
  }

  private static void assertObjEquals(String label, Object expected, Object actual) {
    if (!Objects.equals(expected, actual)) {
      throw new RuntimeException(label + ": is '" + actual + "', but expected '" + expected + "'");
    }
  }

  private static List<String> getUris(List<String> uris) {
    if (uris == null) {
      return null;
    }
    for (String uri : uris) {
      if (CaManager.NULL.equalsIgnoreCase(uri)) {
        return Collections.emptyList();
      }
    }
    return new ArrayList<>(uris);
  }

  private static void formatValidationIssue(
      ValidationIssue issue, String prefix, StringBuilder sb) {
    sb.append(prefix).append(issue.getCode()).append(", ").append(issue.getDescription());
    sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
    if (issue.getFailureMessage() != null) {
      sb.append(", ").append(issue.getFailureMessage());
    }
  }
}
