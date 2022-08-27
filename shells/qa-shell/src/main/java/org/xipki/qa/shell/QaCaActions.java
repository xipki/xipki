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

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.apache.karaf.shell.support.completers.StringsCompleter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.ca.mgmt.shell.*;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.*;
import org.xipki.qa.ca.CaEnrollBenchEntry.RandomDn;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.DSAKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.ECKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.RSAKeyEntry;
import org.xipki.security.EdECConstants;
import org.xipki.security.X509Cert;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Base64;
import org.xipki.util.*;

import java.io.File;
import java.rmi.UnexpectedException;
import java.util.*;

/**
 * Actions of QA for CA.
 *
 * @author Lijun Liao
 */

public class QaCaActions {

  @Command(scope = "caqa", name = "init", description = "initialize the CA QA manager")
  @Service
  public static class Init extends XiAction {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Object execute0() throws Exception {
      boolean succ = qaSystemManager.init();
      if (succ) {
        println("CA QA system initialized successfully");
      } else {
        println("CA QA system initialization failed");
      }
      return null;
    } // method execute0

  } // class Init

  @Command(scope = "caqa", name = "check-cert", description = "check the certificate")
  @Service
  public static class CheckCert extends XiAction {

    @Option(name = "--cert", aliases = "-c", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--issuer", description = "issuer name\n(required if multiple issuers are configured)")
    @Completion(QaCompleters.IssuerNameCompleter.class)
    private String issuerName;

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p", required = true, description = "certificate profile")
    @Completion(QaCompleters.CertprofileNameCompleter.class)
    private String profileName;

    @Option(name = "--verbose", aliases = "-v", description = "show status verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Object execute0() throws Exception {
      Set<String> issuerNames = qaSystemManager.getIssuerNames();
      if (isEmpty(issuerNames)) {
        throw new IllegalCmdParamException("no issuer is configured");
      }

      if (issuerName == null) {
        if (issuerNames.size() != 1) {
          throw new IllegalCmdParamException("no issuer is specified");
        }

        issuerName = issuerNames.iterator().next();
      }

      if (!issuerNames.contains(issuerName)) {
        throw new IllegalCmdParamException("issuer " + issuerName
            + " is not within the configured issuers " + issuerNames);
      }

      IssuerInfo issuerInfo = qaSystemManager.getIssuer(issuerName);

      CertprofileQa qa = qaSystemManager.getCertprofile(profileName);
      if (qa == null) {
        throw new IllegalCmdParamException("found no certificate profile named '" + profileName + "'");
      }

      CertificationRequest csr = X509Util.parseCsr(new File(csrFile));
      Extensions extensions = null;
      CertificationRequestInfo reqInfo = csr.getCertificationRequestInfo();
      ASN1Set attrs = reqInfo.getAttributes();
      for (int i = 0; i < attrs.size(); i++) {
        Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
        if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
          extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
        }
      }

      byte[] certBytes = IoUtil.read(certFile);
      ValidationResult result = qa.checkCert(certBytes, issuerInfo, reqInfo.getSubject(),
          reqInfo.getSubjectPublicKeyInfo(), extensions);
      StringBuilder sb = new StringBuilder();

      sb.append(certFile).append(" (certprofile ").append(profileName).append(")\n");
      sb.append("\tcertificate is ");
      sb.append(result.isAllSuccessful() ? "valid" : "invalid");

      if (verbose.booleanValue()) {
        for (ValidationIssue issue : result.getValidationIssues()) {
          sb.append("\n");
          format(issue, "    ", sb);
        }
      } else {
        for (ValidationIssue issue : result.getValidationIssues()) {
          if (issue.isFailed()) {
            sb.append("\n");
            format(issue, "    ", sb);
          }
        }
      }

      println(sb.toString());
      if (!result.isAllSuccessful()) {
        throw new CmdFailure("certificate is invalid");
      }
      return null;
    } // method execute0

    private static void format(ValidationIssue issue, String prefix, StringBuilder sb) {
      sb.append(prefix).append(issue.getCode());
      sb.append(", ").append(issue.getDescription());
      sb.append(", ").append(issue.isFailed() ? "failed" : "successful");
      if (issue.getFailureMessage() != null) {
        sb.append(", ").append(issue.getFailureMessage());
      }
    }

  } // class CheckCert

  @Command(scope = "caqa", name = "caalias-check", description = "check CA aliases (QA)")
  @Service
  public static class CaAliasCheck extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--alias", required = true, description = "alias name")
    private String aliasName;

    @Override
    protected Object execute0() throws Exception {
      println("checking CA alias='" + aliasName + "', CA='" + caName + "'");
      String tmpCaName = caManager.getCaNameForAlias(aliasName);
      if (tmpCaName == null) {
        throw new CmdFailure("alias '" + aliasName + "' is not configured");
      }

      assertEquals("CA name", caName, tmpCaName);
      println(" checked CA alias='" + aliasName + "', CA='" + caName + "'");
      return null;
    }

  } // class CaAliasCheck

  private static abstract  class AbstractCmpBenchmarkEnroll extends XiAction {

    @Option(name = "--profile", aliases = "-p", required = true,
            description = "certificate profile that allows duplication of public key")
    protected String certprofile;

    @Option(name = "--subject", aliases = "-s", required = true, description = "subject template")
    protected String subjectTemplate;

    @Option(name = "--random-dn", description = "DN name to be incremented")
    @Completion(value = StringsCompleter.class,
        values = {"GIVENNAME", "SURNAME", "STREET", "POSTALCODE", "O", "OU", "CN"})
    protected String randomDnStr = "O";

    @Option(name = "--duration", description = "duration")
    protected String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    protected Integer numThreads = 5;

    @Option(name = "-n", description = "number of certificates to be requested in one request")
    protected Integer num = 1;

    @Option(name = "--max-num", description = "maximal number of requests\n0 for unlimited")
    protected Integer maxRequests = 0;

    @Option(name = "--queue-size", description = "Number of maximal HTTP requests in the sending queue")
    protected Integer queueSize = 50;
  }

  @Command(scope = "xiqa", name = "cmp-benchmark-cagen-enroll", description = "CA client enroll (benchmark)")
  @Service
  public static class CmpBenchmarkCaGenEnroll extends AbstractCmpBenchmarkEnroll {
    @Override
    protected Object execute0() throws Exception {
      if (numThreads < 1) {
        throw new IllegalCmdParamException("invalid number of threads " + numThreads);
      }

      String description = StringUtil.concatObjectsCap(200, "subjectTemplate: ", subjectTemplate,
              "\nprofile: ", certprofile, "\nmaxRequests: ", maxRequests);

      RandomDn randomDn = null;
      if (randomDnStr != null) {
        randomDn = RandomDn.getInstance(randomDnStr);
        if (randomDn == null) {
          throw new IllegalCmdParamException("invalid randomDn " + randomDnStr);
        }
      }

      CaEnrollBenchEntry benchmarkEntry = new CaEnrollBenchEntry(certprofile, null, subjectTemplate, randomDn);
      CaEnrollBenchmark benchmark = new CaEnrollBenchmark(benchmarkEntry, maxRequests, num, queueSize, description);

      benchmark.setDuration(duration);
      benchmark.setThreads(numThreads);
      benchmark.execute();

      return null;
    } // method execute0
  }

  @Command(scope = "xiqa", name = "cmp-benchmark-enroll",
      description = "CA client enroll (benchmark)")
  @Service
  public static class CmpBenchmarkEnroll extends AbstractCmpBenchmarkEnroll {

    @Completion(value = StringsCompleter.class, values = {"RSA", "EC", "DSA"})
    @Option(name = "--key-type", description = "key type to be requested")
    private String keyType = "RSA";

    @Option(name = "--key-size", description = "modulus length of RSA key or p length of DSA key")
    private Integer keysize = 2048;

    @Option(name = "--curve", description = "EC curve name or OID of EC key")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Override
    protected Object execute0() throws Exception {
      if (numThreads < 1) {
        throw new IllegalCmdParamException("invalid number of threads " + numThreads);
      }

      if ("EC".equalsIgnoreCase(keyType) && StringUtil.isBlank(curveName)) {
        throw new IllegalCmdParamException("curveName is not specified");
      }

      String description = StringUtil.concatObjectsCap(200, "subjectTemplate: ", subjectTemplate,
          "\nprofile: ", certprofile, "\nkeyType: ", keyType, "\nmaxRequests: ", maxRequests);

      RandomDn randomDn = null;
      if (randomDnStr != null) {
        randomDn = RandomDn.getInstance(randomDnStr);
        if (randomDn == null) {
          throw new IllegalCmdParamException("invalid randomDn " + randomDnStr);
        }
      }

      CaEnrollBenchKeyEntry keyEntry;
      if ("EC".equalsIgnoreCase(keyType)) {
        ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
        if (curveOid == null) {
          curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
        }
        keyEntry = new ECKeyEntry(curveOid);
      } else if ("RSA".equalsIgnoreCase(keyType)) {
        keyEntry = new RSAKeyEntry(keysize.intValue());
      } else if ("DSA".equalsIgnoreCase(keyType)) {
        keyEntry = new DSAKeyEntry(keysize.intValue());
      } else {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      CaEnrollBenchEntry benchmarkEntry = new CaEnrollBenchEntry(certprofile, keyEntry, subjectTemplate, randomDn);
      CaEnrollBenchmark benchmark = new CaEnrollBenchmark(benchmarkEntry, maxRequests, num, queueSize, description);

      benchmark.setDuration(duration);
      benchmark.setThreads(numThreads);
      benchmark.execute();

      return null;
    } // method execute0

  } // class CmpBenchmarkEnroll

  @Command(scope = "caqa", name = "ca-check", description = "check information of CAs (QA)")
  @Service
  public static class CaCheck extends CaActions.CaUp {

    @Override
    protected Object execute0() throws Exception {
      ChangeCaEntry ey = getChangeCaEntry();
      String caName = ey.getIdent().getName();
      println("checking CA " + caName);

      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      CaUris eyUris = ey.getCaUris();
      // CA cert uris
      if (eyUris != null) {
        assertObjEquals("CA URIs", ey.getCaUris(), ca.getCaUris());
      }

      // CA certificate
      if (ey.getEncodedCert() != null) {
        if (!certEquals(ey.getEncodedCert(), ca.getCert().getEncoded())) {
          throw new CmdFailure("CA cert is not as expected");
        }
      }

      // Certchain
      if (ey.getEncodedCertchain() != null) {
        List<byte[]> eyList = ey.getEncodedCertchain();
        List<X509Cert> isList = ca.getCertchain();
        int eySize = eyList == null ? 0 : eyList.size();
        int isSize = isList == null ? 0 : isList.size();

        if (eySize != isSize) {
          if (CollectionUtil.isNotEmpty(ca.getCertchain())) {
            throw new CmdFailure("Length of CA certchain " + isSize + " is not as expected " + eySize);
          }
        } else if (eySize != 0) {
          for (int i = 0; i < eySize; i++) {
            if (!certEquals(eyList.get(i), isList.get(i).getEncoded())) {
              throw new CmdFailure("CA cert chain[" + i + "] is not as expected");
            }
          }
        }
      }

      // SN size
      if (ey.getSerialNoLen() != null) {
        assertObjEquals("serial number length", ey.getSerialNoLen(), ca.getSerialNoLen());
      }

      // CRL control name
      if (ey.getCrlControl() != null) {
        assertObjEquals("CRL control", new CrlControl(ey.getCrlControl()), ca.getCrlControl());
      }

      // CRL signer name
      if (ey.getCrlSignerName() != null) {
        assertEquals("CRL signer name", ey.getCrlSignerName(), ca.getCrlSignerName());
      }

      // Expiration period
      if (ey.getExpirationPeriod() != null) {
        assertObjEquals("Expiration period", ey.getExpirationPeriod(), ca.getExpirationPeriod());
      }

      // Extra control
      if (ey.getExtraControl() != null) {
        assertObjEquals("Extra control", ey.getExtraControl(), ca.getExtraControl());
      }

      // Max validity
      if (ey.getMaxValidity() != null) {
        assertObjEquals("Max validity", ey.getMaxValidity(), ca.getMaxValidity());
      }

      // Keep expired certificate
      if (ey.getKeepExpiredCertInDays() != null) {
        assertObjEquals("keepExiredCertInDays", ey.getKeepExpiredCertInDays(), ca.getKeepExpiredCertInDays());
      }

      // Num CRLs
      if (ey.getNumCrls() != null) {
        assertObjEquals("num CRLs", ey.getNumCrls(), ca.getNumCrls());
      }

      // Permissions
      if (ey.getPermission() != null) {
        assertObjEquals("permission", ey.getPermission(), ca.getPermission());
      }

      // Signer Type
      if (ey.getSignerType() != null) {
        assertTypeEquals("signer type", ey.getSignerType(), ca.getSignerType());
      }

      if (ey.getSignerConf() != null) {
        ConfPairs ex = new ConfPairs(ey.getSignerConf());
        ex.removePair("keystore");
        ConfPairs is = new ConfPairs(ca.getSignerConf());
        is.removePair("keystore");
        assertObjEquals("signer conf", ex, is);
      }

      // Status
      if (ey.getStatus() != null) {
        assertObjEquals("status", ey.getStatus(), ca.getStatus());
      }

      // validity mode
      if (ey.getValidityMode() != null) {
        assertObjEquals("validity mode", ey.getValidityMode(), ca.getValidityMode());
      }

      println(" checked CA" + caName);
      return null;
    } // method execute0

  } // class CaCheck

  @Command(scope = "caqa", name = "caprofile-check",
      description = "check information of certificate profiles in given CA (QA)")
  @Service
  public static class CaprofileCheck extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String profileName;

    @Override
    protected Object execute0() throws Exception {
      println("checking CA profile CA='" + caName + "', profile='" + profileName + "'");

      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      Set<String> entries = caManager.getCertprofilesForCa(caName);
      if (!entries.contains(profileName.toLowerCase())) {
        throw new CmdFailure("CA is not associated with profile '" + profileName + "'");
      }

      println(" checked CA profile CA='" + caName + "', profile='" + profileName + "'");
      return null;
    }

  } // class CaprofileCheck

  @Command(scope = "caqa", name = "capub-check", description = "check information of publishers in given CA (QA)")
  @Service
  public static class CapubCheck extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String publisherName;

    @Override
    protected Object execute0() throws Exception {
      println("checking CA publisher CA='" + caName + "', publisher='" + publisherName + "'");

      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      List<PublisherEntry> entries = caManager.getPublishersForCa(caName);

      String upPublisherName = publisherName.toLowerCase();
      for (PublisherEntry m : entries) {
        if (m.getIdent().getName().equals(upPublisherName)) {
          println(" checked CA publisher CA='" + caName + "', publisher='" + publisherName + "'");
          return null;
        }
      }

      throw new CmdFailure("CA is not associated with publisher '" + publisherName + "'");
    }

  } // class CapubCheck

  @Command(scope = "caqa", name = "careq-check", description = "check information of requestors in CA (QA)")
  @Service
  public static class CaReqCheck extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(name = "--permission", multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", multiValued = true,
        description = "profile name or 'all' for all profiles, and 'null' for no profiles")
    @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
      println("checking CA requestor CA='" + caName + "', requestor='" + requestorName + "'");

      if (caManager.getCa(caName) == null) {
        throw new UnexpectedException("could not find CA '" + caName + "'");
      }

      Set<CaHasRequestorEntry> entries = caManager.getRequestorsForCa(caName);
      CaHasRequestorEntry entry = null;
      String upRequestorName = requestorName.toLowerCase();
      for (CaHasRequestorEntry m : entries) {
        if (m.getRequestorIdent().getName().equals(upRequestorName)) {
          entry = m;
          break;
        }
      }

      if (entry == null) {
        throw new CmdFailure("CA is not associated with requestor '" + requestorName + "'");
      }

      if (permissions != null) {
        int intPermission = ShellUtil.getPermission(permissions);

        if (intPermission != entry.getPermission()) {
          throw new CmdFailure("permissions: is '" + entry.getPermission() + "', but expected '" + intPermission + "'");
        }
      }

      if (profiles != null) {
        if (profiles.size() == 1) {
          if (CaManager.NULL.equalsIgnoreCase(profiles.iterator().next())) {
            profiles = Collections.emptySet();
          }
        }

        if (!profiles.equals(entry.getProfiles())) {
          throw new CmdFailure("profiles: is '" + entry.getProfiles() + "', but expected '" + profiles + "'");
        }
      }

      println(" checked CA requestor CA='" + caName + "', requestor='" + requestorName + "'");
      return null;
    } // method execute0

  } // class CaReqCheck

  @Command(scope = "caqa", name = "profile-check", description = "check information of profiles (QA)")
  @Service
  public static class ProfileCheck extends ProfileCaActions.ProfileUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking profile " + name);

      if (type == null && conf == null && confFile == null) {
        System.out.println("nothing to update");
        return null;
      }

      if (conf == null && confFile != null) {
        conf = StringUtil.toUtf8String(IoUtil.read(confFile));
      }

      CertprofileEntry cp = caManager.getCertprofile(name);
      if (cp == null) {
        throw new CmdFailure("certificate profile named '" + name + "' is not configured");
      }

      assertTypeEquals("type", type == null ? "xijson" : type, cp.getType());
      assertEquals("conf", conf, cp.getConf());
      println(" checked profile " + name);
      return null;
    }

  } // class ProfileCheck

  @Command(scope = "caqa", name = "publisher-check", description = "check information of publishers (QA)")
  @Service
  public static class PublisherCheck extends PublisherCaActions.PublisherUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking publisher " + name);

      PublisherEntry cp = caManager.getPublisher(name);
      if (cp == null) {
        throw new CmdFailure("publisher named '" + name + "' is not configured");
      }

      if (cp.getType() != null) {
        assertTypeEquals("type", type, cp.getType());
      }

      if (cp.getConf() != null) {
        assertEquals("signer conf", conf, cp.getConf());
      }

      println(" checked publisher " + name);
      return null;
    }

  } // class PublisherCheck

  @Command(scope = "caqa", name = "requestor-check", description = "check information of requestors (QA)")
  @Service
  public static class RequestorCheck extends RequestorCaActions.RequestorUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking requestor " + name);

      RequestorEntry cr = caManager.getRequestor(name);
      if (cr == null) {
        throw new CmdFailure("requestor named '" + name + "' is not configured");
      }

      byte[] ex = IoUtil.read(certFile);
      String expType = RequestorEntry.TYPE_CERT;
      if (!cr.getType().equals(expType)) {
        throw new CmdFailure("IdNameTypeConf type is not " + expType);
      }

      String conf = cr.getConf();
      if (conf == null) {
        throw new CmdFailure("CaCert: is not configured explicitly as expected");
      }

      if (!certEquals(ex, Base64.decode(conf))) {
        throw new CmdFailure("CaCert: the expected one and the actual one differ");
      }

      println(" checked requestor " + name);
      return null;
    } // method execute0

  } // class RequestorCheck

  @Command(scope = "caqa", name = "signer-check", description = "check information of signer (QA)")
  @Service
  public static class SignerCheck extends SignerCaActions.SignerUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking signer " + name);

      SignerEntry cr = caManager.getSigner(name);
      if (cr == null) {
        throw new CmdFailure("signer named '" + name + "' is not configured");
      }

      if (CaManager.NULL.equalsIgnoreCase(certFile)) {
        if (cr.getBase64Cert() != null) {
          throw new CmdFailure("CaCert: is configured but expected is none");
        }
      } else if (certFile != null) {
        byte[] ex = IoUtil.read(certFile);
        if (cr.getBase64Cert() == null) {
          throw new CmdFailure("CaCert: is not configured explicitly as expected");
        }
        if (!certEquals(ex, Base64.decode(cr.getBase64Cert()))) {
          throw new CmdFailure("CaCert: the expected one and the actual one differ");
        }
      }

      String signerConf = getSignerConf();
      if (signerConf != null) {
        assertEquals("conf", signerConf, cr.getConf());
      }

      println(" checked signer " + name);
      return null;
    }

  } // class SignerCheck

  private static void assertTypeEquals(String desc, String ex, String is)
      throws CmdFailure {
    String tmpEx = ex;
    if (CaManager.NULL.equals(tmpEx)) {
      tmpEx = null;
    }

    boolean bo = (tmpEx == null) ? (is == null) : tmpEx.equalsIgnoreCase(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + tmpEx + "'");
    }
  } // method assertTypeEquals

  private static void assertEquals(String desc, String ex, String is)
      throws CmdFailure {
    String tmpEx = ex;
    if (CaManager.NULL.equals(tmpEx)) {
      tmpEx = null;
    }

    boolean bo = Objects.equals(tmpEx, is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + tmpEx + "'");
    }
  } // method assertEquals

  private static void assertObjEquals(String desc, Object ex, Object is)
      throws CmdFailure {
    boolean bo = Objects.equals(ex, is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + ex + "'");
    }
  } // method assertObjEquals

  private static boolean certEquals(byte[] certBytes1, byte[] certBytes2) {
    if (certBytes1 == null && certBytes2 == null) {
      return true;
    } else if (certBytes1 != null && certBytes2 != null) {
      try {
        byte[] encoded1 = X509Util.parseCert(certBytes1).getEncoded();
        byte[] encoded2 = X509Util.parseCert(certBytes2).getEncoded();
        return Arrays.equals(encoded1, encoded2);
      } catch (Exception ex) {
        return false;
      }
    } else {
      return false;
    }
  } // method certEquals

}
