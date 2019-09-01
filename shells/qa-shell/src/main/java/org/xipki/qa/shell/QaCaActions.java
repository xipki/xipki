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

package org.xipki.qa.shell;

import java.io.File;
import java.rmi.UnexpectedException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
import org.xipki.ca.api.mgmt.CmpControl;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.mgmt.shell.CaActions;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.ca.mgmt.shell.CaCompleters;
import org.xipki.ca.mgmt.shell.CertActions.EnrollCert;
import org.xipki.ca.mgmt.shell.CertActions.RevokeCert;
import org.xipki.ca.mgmt.shell.CertActions.RmCert;
import org.xipki.ca.mgmt.shell.CertActions.UnrevokeCert;
import org.xipki.ca.mgmt.shell.ShellUtil;
import org.xipki.qa.ValidationIssue;
import org.xipki.qa.ValidationResult;
import org.xipki.qa.ca.CaEnrollBenchEntry;
import org.xipki.qa.ca.CaEnrollBenchEntry.RandomDn;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.DSAKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.ECKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchKeyEntry.RSAKeyEntry;
import org.xipki.qa.ca.CaEnrollBenchmark;
import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ca.CertprofileQa;
import org.xipki.qa.ca.IssuerInfo;
import org.xipki.security.EdECConstants;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

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

    @Option(name = "--issuer",
        description = "issuer name\n(required if multiple issuers are configured)")
    @Completion(QaCompleters.IssuerNameCompleter.class)
    private String issuerName;

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--profile", aliases = "-p", required = true,
        description = "certificate profile")
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
        throw new IllegalCmdParamException("found no certificate profile named '"
            + profileName + "'");
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

  @Command(scope = "xiqa", name = "cmp-benchmark-enroll",
      description = "CA client enroll (benchmark)")
  @Service
  public static class CmpBenchmarkEnroll extends XiAction {

    @Option(name = "--profile", aliases = "-p", required = true,
        description =  "certificate profile that allows duplication of public key")
    private String certprofile;

    @Option(name = "--subject", aliases = "-s", required = true, description = "subject template")
    private String subjectTemplate;

    @Option(name = "--random-dn", description = "DN name to be incremented")
    @Completion(value = StringsCompleter.class, values = {"GIVENNAME", "SURNAME", "STREET",
        "POSTALCODE", "O", "OU", "CN"})
    private String randomDnStr = "O";

    @Option(name = "--duration", description = "duration")
    private String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Completion(value = StringsCompleter.class, values = {"RSA", "EC", "DSA"})
    @Option(name = "--key-type", description = "key type to be requested")
    private String keyType = "RSA";

    @Option(name = "--key-size", description = "modulus length of RSA key or p length of DSA key")
    private Integer keysize = 2048;

    @Option(name = "--curve", description = "EC curve name or OID of EC key")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Option(name = "-n", description = "number of certificates to be requested in one request")
    private Integer num = 1;

    @Option(name = "--max-num", description = "maximal number of requests\n0 for unlimited")
    private Integer maxRequests = 0;

    @Option(name = "--queue-size",
        description = "Number of maximal HTTP requests in the sending queue\n"
            + "0 for implemention default")
    private Integer queueSize = 0;

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

      CaEnrollBenchEntry benchmarkEntry = new CaEnrollBenchEntry(certprofile, keyEntry,
          subjectTemplate, randomDn);
      CaEnrollBenchmark benchmark = new CaEnrollBenchmark(benchmarkEntry, maxRequests, num,
          queueSize, description);

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
      MgmtEntry.ChangeCa ey = getChangeCaEntry();
      String caName = ey.getIdent().getName();
      println("checking CA " + caName);

      MgmtEntry.Ca ca = caManager.getCa(caName);
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
        List<X509Certificate> isList = ca.getCertchain();
        int eySize = eyList == null ? 0 : eyList.size();
        int isSize = isList == null ? 0 : isList.size();

        if (eySize != isSize) {
          if (CollectionUtil.isNotEmpty(ca.getCertchain())) {
            throw new CmdFailure("Length of CA certchain " + isSize
                + " is not as expected " + eySize);
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
      if (ey.getSerialNoBitLen() != null) {
        assertObjEquals("serial number bit length", ey.getSerialNoBitLen(), ca.getSerialNoBitLen());
      }

      // CMP control name
      if (ey.getCmpControl() != null) {
        assertObjEquals("CMP control", new CmpControl(ey.getCmpControl()), ca.getCmpControl());
      }

      // CRL control name
      if (ey.getCrlControl() != null) {
        assertObjEquals("CRL control", new CmpControl(ey.getCrlControl()), ca.getCrlControl());
      }

      // CMP responder name
      if (ey.getCmpResponderName() != null) {
        assertEquals("CMP responder name",
            ey.getCmpResponderName(), ca.getCmpResponderName());
      }

      // SCEP responder name
      if (ey.getScepResponderName() != null) {
        assertEquals("SCEP responder name",
            ey.getScepResponderName(), ca.getScepResponderName());
      }

      // CRL signer name
      if (ey.getCrlSignerName() != null) {
        assertEquals(
            "CRL signer name", ey.getCrlSignerName(), ca.getCrlSignerName());
      }

      // Duplicate key mode
      if (ey.getDuplicateKeyPermitted() != null) {
        assertObjEquals("Duplicate key permitted",
            ey.getDuplicateKeyPermitted(), ca.isDuplicateKeyPermitted());
      }

      // Duplicate subject mode
      if (ey.getDuplicateSubjectPermitted() != null) {
        assertObjEquals("Duplicate subject permitted",
            ey.getDuplicateSubjectPermitted(), ca.isDuplicateSubjectPermitted());
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
        assertObjEquals("keepExiredCertInDays",
            ey.getKeepExpiredCertInDays(), ca.getKeepExpiredCertInDays());
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

  @Command(scope = "caqa", name = "capub-check",
      description = "check information of publishers in given CA (QA)")
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

      List<MgmtEntry.Publisher> entries = caManager.getPublishersForCa(caName);

      String upPublisherName = publisherName.toLowerCase();
      for (MgmtEntry.Publisher m : entries) {
        if (m.getIdent().getName().equals(upPublisherName)) {
          println(" checked CA publisher CA='" + caName + "', publisher='" + publisherName + "'");
          return null;
        }
      }

      throw new CmdFailure("CA is not associated with publisher '" + publisherName + "'");
    }

  } // class CapubCheck

  @Command(scope = "caqa", name = "careq-check",
      description = "check information of requestors in CA (QA)")
  @Service
  public static class CaReqCheck extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(name = "--ra", description = "whether as RA")
    @Completion(Completers.YesNoCompleter.class)
    private String raS = "no";

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

      Set<MgmtEntry.CaHasRequestor> entries = caManager.getRequestorsForCa(caName);
      MgmtEntry.CaHasRequestor entry = null;
      String upRequestorName = requestorName.toLowerCase();
      for (MgmtEntry.CaHasRequestor m : entries) {
        if (m.getRequestorIdent().getName().equals(upRequestorName)) {
          entry = m;
          break;
        }
      }

      if (entry == null) {
        throw new CmdFailure("CA is not associated with requestor '" + requestorName + "'");
      }

      boolean ra = isEnabled(raS, false, "ra");
      boolean bo = entry.isRa();
      if (ra != bo) {
        throw new CmdFailure("ra: is '" + bo + "', expected '" + ra + "'");
      }

      if (permissions != null) {
        int intPermission = ShellUtil.getPermission(permissions);

        if (intPermission != entry.getPermission()) {
          throw new CmdFailure("permissions: is '" + entry.getPermission()
              + "', but expected '" + intPermission + "'");
        }
      }

      if (profiles != null) {
        if (profiles.size() == 1) {
          if (CaManager.NULL.equalsIgnoreCase(profiles.iterator().next())) {
            profiles = Collections.emptySet();
          }
        }

        if (!profiles.equals(entry.getProfiles())) {
          throw new CmdFailure("profiles: is '" + entry.getProfiles()
              + "', but expected '" + profiles + "'");
        }
      }

      println(" checked CA requestor CA='" + caName + "', requestor='" + requestorName + "'");
      return null;
    } // method execute0

  } // class CaReqCheck

  @Command(scope = "caqa", name = "neg-ca-add", description = "add CA (negative, QA)")
  @Service
  public static class NegCaAdd extends CaActions.CaAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-ca-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaAdd

  @Command(scope = "caqa", name = "neg-caalias-add", description = "add CA alias (negative, QA)")
  @Service
  public static class NegCaaliasAdd extends CaActions.CaaliasAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-caalias-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaaliasAdd

  @Command(scope = "caqa", name = "neg-caalias-rm", description = "remove CA alias (negative, QA)")
  @Service
  public static class NegCaaliasRm extends CaActions.CaaliasRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-caalias-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaaliasRm

  @Command(scope = "caqa", name = "neg-caprofile-add",
      description = "add certificate profiles to CA (negative, QA)")
  @Service
  public static class NegCaprofileAdd extends CaActions.CaprofileAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-caprofile-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaprofileAdd

  @Command(scope = "caqa", name = "neg-caprofile-rm",
      description = "remove certificate profile from CA (negative, QA)")
  @Service
  public static class NegCaprofileRm extends CaActions.CaprofileRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-caprofile-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaprofileRm

  @Command(scope = "caqa", name = "neg-capub-add",
      description = "add publishers to CA (negative, QA)")
  @Service
  public static class NegCaPubAdd extends CaActions.CapubAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-capub-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaPubAdd

  @Command(scope = "caqa", name = "neg-capub-rm",
      description = "remove publisher from CA (negative, QA)")
  @Service
  public static class NegCapubRm extends CaActions.CapubRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-capub-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCapubRm

  @Command(scope = "caqa", name = "neg-ca-rm", description = "remove CA (negative, QA)")
  @Service
  public static class NegCaRm extends CaActions.CaRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-ca-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaRm

  @Command(scope = "caqa", name = "neg-careq-add",
      description = "add requestor to CA (negative, QA)")
  @Service
  public static class NegCaReqAdd extends CaActions.CareqAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-careq-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaReqAdd

  @Command(scope = "caqa", name = "neg-careq-rm",
      description = "remove requestor in CA (negative, QA)")
  @Service
  public static class NegCareqRm extends CaActions.CareqRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-careq-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCareqRm

  @Command(scope = "caqa", name = "neg-ca-revoke", description = "revoke CA (negative, QA)")
  @Service
  public static class NegCaRevoke extends CaActions.CaRevoke {

    @Override
    protected Object execute0() throws Exception {
      println("neg-ca-revoke");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaRevoke

  @Command(scope = "caqa", name = "neg-ca-unrevoke", description = "unrevoke CA (negative, QA)")
  @Service
  public static class NegCaUnrevoke extends CaActions.CaUnrevoke {

    @Override
    protected Object execute0() throws Exception {
      println("neg-ca-unrevoke");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaUnrevoke

  @Command(scope = "caqa", name = "neg-ca-up", description = "update CA (negative, QA)")
  @Service
  public static class NegCaUp extends CaActions.CaUp {

    @Override
    protected Object execute0() throws Exception {
      println("neg-ca-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegCaUp

  @Command(scope = "caqa", name = "neg-clear-publishqueue",
      description = "clear publish queue (negative, QA)")
  @Service
  public static class NegClearPublishQueue extends CaActions.ClearPublishqueue {

    @Override
    protected Object execute0() throws Exception {
      println("neg-clear-publishqueue");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegClearPublishQueue

  @Command(scope = "caqa", name = "neg-enroll-cert",
      description = "enroll certificate (negative, QA)")
  @Service
  public static class NegEnrollCert extends EnrollCert {

    @Override
    protected Object execute0() throws Exception {
      println("neg-enroll-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegEnrollCert

  @Command(scope = "caqa", name = "neg-gen-rootca",
      description = "generate selfsigned CA (negative, QA)")
  @Service
  public static class NegGenRootCa extends CaActions.GenRootca {

    @Override
    protected Object execute0() throws Exception {
      println("neg-gen-rootca");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegGenRootCa

  @Command(scope = "caqa", name = "neg-profile-add",
      description = "add certificate profile (negative, QA)")
  @Service
  public static class NegProfileAdd extends CaActions.ProfileAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-profile-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileAdd

  @Command(scope = "caqa", name = "profile-check",
      description = "check information of profiles (QA)")
  @Service
  public static class ProfileCheck extends CaActions.ProfileUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking profile " + name);

      if (type == null && conf == null && confFile == null) {
        System.out.println("nothing to update");
        return null;
      }

      if (conf == null && confFile != null) {
        conf = new String(IoUtil.read(confFile));
      }

      MgmtEntry.Certprofile cp = caManager.getCertprofile(name);
      if (cp == null) {
        throw new CmdFailure("certificate profile named '" + name + "' is not configured");
      }

      if (cp.getType() != null) {
        assertTypeEquals("type", type, cp.getType());
      }

      assertEquals("conf", conf, cp.getConf());

      println(" checked profile " + name);
      return null;
    }

  } // class ProfileCheck

  @Command(scope = "caqa", name = "neg-profile-rm", description = "remove Profile (negative, QA)")
  @Service
  public static class NegProfileRm extends CaActions.ProfileRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-profile-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileRm

  @Command(scope = "caqa", name = "neg-profile-up",
      description = "update certificate profile (negative, QA)")
  @Service
  public static class NegProfileUp extends CaActions.ProfileUp {

    @Override
    protected Object execute0() throws Exception {
      println("neg-profile-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegProfileUp

  @Command(scope = "caqa", name = "neg-publisher-add", description = "add publisher (negative, QA)")
  @Service
  public static class NegPublisherAdd extends CaActions.PublisherAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-publisher-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherAdd

  @Command(scope = "caqa", name = "publisher-check",
      description = "check information of publishers (QA)")
  @Service
  public static class PublisherCheck extends CaActions.PublisherUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking publisher " + name);

      MgmtEntry.Publisher cp = caManager.getPublisher(name);
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

  @Command(scope = "caqa", name = "neg-publisher-rm",
      description = "remove publisher (negative, QA)")
  @Service
  public static class NegPublisherRm extends CaActions.PublisherRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-publisher-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherRm

  @Command(scope = "caqa", name = "neg-publisher-up",
      description = "update publisher (negative, QA)")
  @Service
  public static class NegPublisherUp extends CaActions.PublisherUp {

    @Override
    protected Object execute0() throws Exception {
      println("neg-publisher-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegPublisherUp

  @Command(scope = "caqa", name = "neg-republish",
      description = "republish certificates (negative, QA)")
  @Service
  public static class NegRepublish extends CaActions.Republish {

    @Override
    protected Object execute0() throws Exception {
      println("neg-republish");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRepublish

  @Command(scope = "caqa", name = "neg-requestor-add", description = "add requestor (negative, QA)")
  @Service
  public static class NegRequestorAdd extends CaActions.RequestorAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-requestor-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorAdd

  @Command(scope = "caqa", name = "requestor-check",
      description = "check information of requestors (QA)")
  @Service
  public static class RequestorCheck extends CaActions.RequestorUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking requestor " + name);

      MgmtEntry.Requestor cr = caManager.getRequestor(name);
      if (cr == null) {
        throw new CmdFailure("requestor named '" + name + "' is not configured");
      }

      if (certFile != null) {
        byte[] ex = IoUtil.read(certFile);
        String expType = MgmtEntry.Requestor.TYPE_CERT;
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
      } else {
        String expType = MgmtEntry.Requestor.TYPE_PBM;
        if (!cr.getType().equals(expType)) {
          throw new CmdFailure("IdNameTypeConf type is not " + expType);
        }

        char[] ex = password.toCharArray();
        char[] is = securityFactory.getPasswordResolver().resolvePassword(cr.getConf());
        if (Arrays.equals(ex, is)) {
          throw new CmdFailure("PBM: the expected one and the actual one differ");
        }
      }

      println(" checked requestor " + name);
      return null;
    } // method execute0

  } // class RequestorCheck

  @Command(scope = "caqa", name = "neg-requestor-rm",
      description = "remove requestor (negative, QA)")
  @Service
  public static class NegRequestorRm extends CaActions.RequestorRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-requestor-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorRm

  @Command(scope = "caqa", name = "neg-requestor-up",
      description = "update requestor (negative, QA)")
  @Service
  public static class NegRequestorUp extends CaActions.RequestorUp {

    @Override
    protected Object execute0() throws Exception {
      println("neg-requestor-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegRequestorUp

  @Command(scope = "caqa", name = "neg-rm-cert", description = "remove certificate (negative, QA)")
  @Service
  public static class NegRmCert extends RmCert {

    @Override
    protected Object execute0() throws Exception {
      println("neg-remove-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegRmCert

  @Command(scope = "caqa", name = "neg-revoke-cert",
      description = "revoke certificate (negative, QA)")
  @Service
  public static class NegRevokeCert extends RevokeCert {

    @Override
    protected Object execute0() throws Exception {
      println("neg-remove-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegRevokeCert

  @Command(scope = "caqa", name = "neg-signer-add", description = "add signer (negative, QA)")
  @Service
  public static class NegSignerAdd extends CaActions.SignerAdd {

    @Override
    protected Object execute0() throws Exception {
      println("neg-signer-add");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerAdd

  @Command(scope = "caqa", name = "signer-check", description = "check information of signer (QA)")
  @Service
  public static class SignerCheck extends CaActions.SignerUp {

    @Override
    protected Object execute0() throws Exception {
      println("checking signer " + name);

      MgmtEntry.Signer cr = caManager.getSigner(name);
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

  @Command(scope = "caqa", name = "neg-signer-rm", description = "remove signer (negative, QA)")
  @Service
  public static class NegSignerRm extends CaActions.SignerRm {

    @Override
    protected Object execute0() throws Exception {
      println("neg-signer-rm");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerRm

  @Command(scope = "caqa", name = "neg-signer-up", description = "update signer (negative, QA)")
  @Service
  public static class NegSignerUp extends CaActions.SignerUp {

    @Override
    protected Object execute0() throws Exception {
      println("neg-signer-up");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("exception expected, but received none");
    }

  } // class NegSignerUp

  @Command(scope = "caqa", name = "neg-unrevoke-cert",
      description = "unrevoke certificate (negative, QA)")
  @Service
  public static class NegUnrevokeCert extends UnrevokeCert {

    @Override
    protected Object execute0() throws Exception {
      println("neg-unrevoke-cert");

      try {
        super.execute0();
      } catch (Exception ex) {
        return null;
      }

      throw new CmdFailure("Exception expected, but received none");
    }

  } // class NegUnrevokeCert

  public static void assertTypeEquals(String desc, String ex, String is) throws CmdFailure {
    String tmpEx = ex;
    if (CaManager.NULL.equals(tmpEx)) {
      tmpEx = null;
    }

    boolean bo = (tmpEx == null) ? (is == null) : tmpEx.equalsIgnoreCase(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + tmpEx + "'");
    }
  } // method assertTypeEquals

  public static void assertEquals(String desc, String ex, String is) throws CmdFailure {
    String tmpEx = ex;
    if (CaManager.NULL.equals(tmpEx)) {
      tmpEx = null;
    }

    boolean bo = (tmpEx == null) ? (is == null) : tmpEx.equals(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + tmpEx + "'");
    }
  } // method assertEquals

  public static void assertEquals(String desc, Collection<?> ex, Collection<?> is)
      throws CmdFailure {
    boolean bo = (ex == null) ? (is == null) : ex.equals(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + ex + "'");
    }
  } // method assertEquals

  public static void assertObjEquals(String desc, Object ex, Object is) throws CmdFailure {
    boolean bo = (ex == null) ? (is == null) : ex.equals(is);
    if (!bo) {
      throw new CmdFailure(desc + ": is '" + is + "', but expected '" + ex + "'");
    }
  } // method assertObjEquals

  public static boolean certEquals(byte[] certBytes1, byte[] certBytes2) {
    if (certBytes1 == null && certBytes2 == null) {
      return true;
    } else if (certBytes1 != null && certBytes2 != null) {
      try {
        byte[] encoded1 = X509Util.parseBcCert(certBytes1).getEncoded();
        byte[] encoded2 = X509Util.parseBcCert(certBytes2).getEncoded();
        return Arrays.equals(encoded1, encoded2);
      } catch (Exception ex) {
        return false;
      }
    } else {
      return false;
    }
  } // method certEquals

}
