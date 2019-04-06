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

package org.xipki.ca.mgmt.shell;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaConfs;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CaSystemStatus;
import org.xipki.ca.api.mgmt.CmpControl;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtLogControl;
import org.xipki.ca.api.mgmt.MgmtEntry;
import org.xipki.ca.api.mgmt.PermissionConstants;
import org.xipki.ca.api.mgmt.ProtocolSupport;
import org.xipki.ca.api.mgmt.ScepControl;
import org.xipki.ca.api.mgmt.ValidityMode;
import org.xipki.password.PasswordResolver;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 *
 */
public class CaActions {

  public abstract static class CaAction extends XiAction {

    @Reference
    protected CaManager caManager;

    @Reference
    protected SecurityFactory securityFactory;

    protected static String getRealString(String str) {
      return CaManager.NULL.equalsIgnoreCase(str) ? null : str;
    }

    protected static String toString(Collection<? extends Object> col) {
      if (col == null) {
        return "null";
      }

      StringBuilder sb = new StringBuilder();
      sb.append("{");
      int size = col.size();

      int idx = 0;
      for (Object o : col) {
        sb.append(o);
        if (idx < size - 1) {
          sb.append(", ");
        }
        idx++;
      }
      sb.append("}");
      return sb.toString();
    }

    protected void printCaNames(StringBuilder sb, Set<String> caNames, String prefix)
        throws CaMgmtException {
      if (caNames.isEmpty()) {
        sb.append(prefix).append("-\n");
        return;
      }

      for (String caName : caNames) {
        Set<String> aliases = caManager.getAliasesForCa(caName);
        if (CollectionUtil.isEmpty(aliases)) {
          sb.append(prefix).append(caName);
        } else {
          sb.append(prefix).append(caName + " (aliases " + aliases + ")");
        }
        sb.append("\n");
      }
    }

  }

  @Command(scope = "ca", name = "ca-add", description = "add CA")
  @Service
  public static class CaAdd extends CaAddOrGenAction {

    @Option(name = "--cert", description = "CA certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--certchain", multiValued = true,
        description = "certificate chain of CA certificate")
    @Completion(FileCompleter.class)
    private List<String> issuerCertFiles;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.Ca caEntry = getCaEntry();
      if (certFile != null) {
        X509Certificate caCert = X509Util.parseCert(new File(certFile));
        caEntry.setCert(caCert);
      }

      if (CollectionUtil.isNonEmpty(issuerCertFiles)) {
        List<X509Certificate> list = new ArrayList<>(issuerCertFiles.size());
        for (String m : issuerCertFiles) {
          list.add(X509Util.parseCert(Paths.get(m).toFile()));
        }
        caEntry.setCertchain(list);
      }

      String msg = "CA " + caEntry.getIdent().getName();
      try {
        caManager.addCa(caEntry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  public abstract static class CaAddOrGenAction extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "CA name")
    private String caName;

    @Option(name = "--status", description = "CA status")
    @Completion(CaCompleters.CaStatusCompleter.class)
    private String caStatus = "active";

    @Option(name = "--rest-status", description = "REST API status")
    @Completion(CaCompleters.CaStatusCompleter.class)
    private String restStatus = "inactive";

    @Option(name = "--ca-cert-uri", multiValued = true, description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI")
    private List<String> ocspUris;

    @Option(name = "--crl-uri", multiValued = true, description = "CRL distribution point")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri", multiValued = true, description = "CRL distribution point")
    private List<String> deltaCrlUris;

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--sn-bitlen",
        description = "number of bits of the serial number, between "
            + CaManager.MIN_SERIALNUMBER_SIZE + " and " + CaManager.MAX_SERIALNUMBER_SIZE)
    private int snBitLen = 127;

    @Option(name = "--next-crl-no", required = true, description = "CRL number for the next CRL")
    private Long nextCrlNumber;

    @Option(name = "--max-validity", required = true, description = "maximal validity")
    private String maxValidity;

    @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
    private Integer keepExpiredCertInDays = -1;

    @Option(name = "--crl-signer", description = "CRL signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String crlSignerName;

    @Option(name = "--precert-signer", description = "Precert (for CT Log) signer name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String precertSignerName;

    @Option(name = "--cmp-responder", description = "CMP responder name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String cmpResponderName;

    @Option(name = "--scep-responder", description = "SCEP responder name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String scepResponderName;

    @Option(name = "--cmp-control", description = "CMP control")
    private String cmpControl;

    @Option(name = "--crl-control", description = "CRL control")
    private String crlControl;

    @Option(name = "--scep-control", description = "SCEP control")
    private String scepControl;

    @Option(name = "--ctlog-control", description = "CT log control")
    private String ctLogControl;

    @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
    private Integer numCrls = 30;

    @Option(name = "--expiration-period",
        description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod = 365;

    @Option(name = "--signer-type", required = true, description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf", required = true, description = "CA signer configuration")
    private String signerConf;

    @Option(name = "--duplicate-key", description = "whether duplicate key is permitted")
    @Completion(Completers.YesNoCompleter.class)
    private String duplicateKeyS = "yes";

    @Option(name = "--duplicate-subject", description = "whether duplicate subject is permitted")
    @Completion(Completers.YesNoCompleter.class)
    private String duplicateSubjectS = "yes";

    @Option(name = "--support-cmp", description = "whether the CMP protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportCmpS = "no";

    @Option(name = "--support-rest", description = "whether the REST protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportRestS = "no";

    @Option(name = "--support-scep", description = "whether the SCEP protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportScepS = "no";

    @Option(name = "--save-req", description = "whether the request is saved")
    @Completion(Completers.YesNoCompleter.class)
    private String saveReqS = "no";

    @Option(name = "--validity-mode", description = "mode of valditity")
    @Completion(CaCompleters.ValidityModeCompleter.class)
    private String validityModeS = "STRICT";

    @Option(name = "--extra-control", description = "extra control")
    private String extraControl;

    @Reference
    private PasswordResolver passwordResolver;

    protected MgmtEntry.Ca getCaEntry() throws Exception {
      Args.range(snBitLen, "sn-bitlen",
          CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);

      if (nextCrlNumber < 1) {
        throw new IllegalCmdParamException("invalid CRL number: " + nextCrlNumber);
      }

      if (numCrls < 0) {
        throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
      }

      if (expirationPeriod < 0) {
        throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
      }

      if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
        signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver,
            securityFactory);
      }

      CaUris caUris = new CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
      MgmtEntry.Ca entry = new MgmtEntry.Ca(new NameId(null, caName), snBitLen, nextCrlNumber,
          signerType, signerConf, caUris, numCrls.intValue(), expirationPeriod.intValue());

      entry.setKeepExpiredCertInDays(keepExpiredCertInDays.intValue());

      boolean duplicateKeyPermitted = isEnabled(duplicateKeyS, true, "duplicate-key");
      entry.setDuplicateKeyPermitted(duplicateKeyPermitted);

      boolean duplicateSubjectPermitted = isEnabled(duplicateSubjectS, true, "duplicate-subject");
      entry.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

      ProtocolSupport protocolSupport = new ProtocolSupport(
          isEnabled(supportCmpS, false, "support-cmp"),
          isEnabled(supportRestS, false, "support-rest"),
          isEnabled(supportScepS, false, "support-scep"));
      entry.setProtocolSupport(protocolSupport);
      entry.setSaveRequest(isEnabled(saveReqS, false, "save-req"));

      ValidityMode validityMode = ValidityMode.forName(validityModeS);
      entry.setValidityMode(validityMode);

      entry.setStatus(CaStatus.forName(caStatus));

      if (cmpControl != null) {
        entry.setCmpControl(new CmpControl(cmpControl));
      }

      if (crlControl != null) {
        entry.setCrlControl(new CrlControl(crlControl));
      }

      if (scepControl != null) {
        entry.setScepControl(new ScepControl(scepControl));
      }

      if (ctLogControl != null) {
        entry.setCtLogControl(new CtLogControl(ctLogControl));
      }

      if (cmpResponderName != null) {
        entry.setCmpResponderName(cmpResponderName);
      }

      if (scepResponderName != null) {
        entry.setCmpResponderName(scepResponderName);
      }

      if (crlSignerName != null) {
        entry.setCrlSignerName(crlSignerName);
      }

      if (precertSignerName != null) {
        entry.setPrecertSignerName(precertSignerName);
      }

      Validity tmpMaxValidity = Validity.getInstance(maxValidity);
      entry.setMaxValidity(tmpMaxValidity);

      entry.setKeepExpiredCertInDays(keepExpiredCertInDays);

      int intPermission = ShellUtil.getPermission(permissions);
      entry.setPermission(intPermission);

      if (extraControl != null) {
        extraControl = extraControl.trim();
      }
      if (StringUtil.isNotBlank(extraControl)) {
        entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
      }
      return entry;
    } // method getCaEntry

  }

  @Command(scope = "ca", name = "caalias-add", description = "add CA alias")
  @Service
  public static class CaaliasAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--alias", required = true, description = "CA alias")
    private String caAlias;

    @Override
    protected Object execute0() throws Exception {
      String msg = "CA alias " + caAlias + " associated with CA " + caName;
      try {
        caManager.addCaAlias(caAlias, caName);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "caalias-info", description = "show information of CA alias")
  @Service
  public static class CaaliasInfo extends CaAction {

    @Argument(index = 0, name = "alias", description = "CA alias")
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String caAlias;

    @Override
    protected Object execute0() throws Exception {
      Set<String> aliasNames = caManager.getCaAliasNames();

      StringBuilder sb = new StringBuilder();

      if (caAlias == null) {
        int size = aliasNames.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1");
          sb.append(" CA alias is configured\n");
        } else {
          sb.append(size).append(" CA aliases are configured:\n");
        }

        List<String> sorted = new ArrayList<>(aliasNames);
        Collections.sort(sorted);

        for (String aliasName : sorted) {
          sb.append("\t").append(aliasName).append("\n");
        }
      } else {
        if (aliasNames.contains(caAlias)) {
          String paramValue = caManager.getCaNameForAlias(caAlias);
          sb.append(caAlias).append("\n\t").append(paramValue);
        } else {
          throw new CmdFailure("could not find CA alias '" + caAlias + "'");
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "caalias-rm", description = "remove CA alias")
  @Service
  public static class CaaliasRm extends CaAction {

    @Argument(index = 0, name = "alias", description = "CA alias", required = true)
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String caAlias;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "CA alias " + caAlias;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCaAlias(caAlias);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "gen-rootca", description = "generate selfsigned CA")
  @Service
  public static class GenRootca extends CaAddOrGenAction {

    @Option(name = "--csr", required = true, description = "CSR of the Root CA")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--profile", required = true, description = "profile of the Root CA")
    private String rootcaProfile;

    @Option(name = "--serial", description = "profile of the Root CA")
    private String serialS;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o",
        description = "where to save the generated CA certificate")
    @Completion(FileCompleter.class)
    private String rootcaCertOutFile;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.Ca caEntry = getCaEntry();
      byte[] csr = IoUtil.read(csrFile);
      BigInteger serialNumber = null;
      if (serialS != null) {
        serialNumber = toBigInt(serialS);
      }

      X509Certificate rootcaCert = caManager.generateRootCa(caEntry, rootcaProfile, csr,
          serialNumber);
      if (rootcaCertOutFile != null) {
        saveVerbose("saved root certificate to file", rootcaCertOutFile,
            encodeCert(rootcaCert.getEncoded(), outform));
      }
      println("generated root CA " + caEntry.getIdent().getName());
      return null;
    }

  }

  @Command(scope = "ca", name = "ca-info", description = "show information of CA")
  @Service
  public static class CaInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v", description = "show CA information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();
      if (name == null) {
        sb.append("successful CAs:\n");
        String prefix = "  ";
        printCaNames(sb, caManager.getSuccessfulCaNames(), prefix);

        sb.append("failed CAs:\n");
        printCaNames(sb, caManager.getFailedCaNames(), prefix);

        sb.append("inactive CAs:\n");
        printCaNames(sb, caManager.getInactiveCaNames(), prefix);
      } else {
        MgmtEntry.Ca entry = caManager.getCa(name);
        if (entry == null) {
          throw new CmdFailure("could not find CA '" + name + "'");
        } else {
          if (CaStatus.ACTIVE == entry.getStatus()) {
            boolean started = caManager.getSuccessfulCaNames().contains(entry.getIdent().getName());
            sb.append("started: ").append(started).append("\n");
          }
          Set<String> aliases = caManager.getAliasesForCa(name);
          sb.append("aliases: ").append(toString(aliases)).append("\n");
          sb.append(entry.toString(verbose.booleanValue()));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "caprofile-add", description = "add certificate profile to CA")
  @Service
  public static class CaprofileAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile", required = true, multiValued = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNames;

    @Override
    protected Object execute0() throws Exception {
      for (String profileName : profileNames) {
        String msg = StringUtil.concat("certificate profile ", profileName, " to CA ", caName);
        try {
          caManager.addCertprofileToCa(profileName, caName);
          println("associated " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not associate " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "caprofile-info",
      description = "show information of certificate profile in given CA")
  @Service
  public static class CaprofileInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      StringBuilder sb = new StringBuilder();
      Set<String> entries = caManager.getCertprofilesForCa(caName);
      if (CollectionUtil.isNonEmpty(entries)) {
        sb.append("certificate Profiles supported by CA " + caName).append("\n");

        for (String name: entries) {
          sb.append("\t").append(name).append("\n");
        }
      } else {
        sb.append("\tno profile for CA " + caName + " is configured");
      }

      println(sb.toString());
      return null;
    }

  }

  @Command(scope = "ca", name = "caprofile-rm", description = "remove certificate profile from CA")
  @Service
  public static class CaprofileRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--profile", required = true, multiValued = true,
        description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private List<String> profileNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String profileName : profileNames) {
        String msg = StringUtil.concat("certificate profile ", profileName, " from CA ", caName);
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removeCertprofileFromCa(profileName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    }

  }

  @Command(scope = "ca", name = "capub-add", description = "add publisher to CA")
  @Service
  public static class CapubAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true,
        description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Override
    protected Object execute0() throws Exception {
      for (String publisherName : publisherNames) {
        String msg = "publisher " + publisherName + " to CA " + caName;
        try {
          caManager.addPublisherToCa(publisherName, caName);
          println("added " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
        }
      }

      return null;
    }

  }

  @Command(scope = "ca", name = "capub-info",
      description = "show information of publisher in given CA")
  @Service
  public static class CapubInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      List<MgmtEntry.Publisher> entries = caManager.getPublishersForCa(caName);
      if (isNotEmpty(entries)) {
        StringBuilder sb = new StringBuilder();
        sb.append("publishers for CA ").append(caName).append("\n");
        for (MgmtEntry.Publisher entry : entries) {
          sb.append("\t").append(entry.getIdent().getName()).append("\n");
        }
        println(sb.toString());
      } else {
        println(StringUtil.concat("no publisher for CA ", caName," is configured"));
      }

      return null;
    }

  }

  @Command(scope = "ca", name = "capub-rm", description = "remove publisher from CA")
  @Service
  public static class CapubRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true,
        description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private List<String> publisherNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String publisherName : publisherNames) {
        String msg = "publisher " + publisherName + " from CA " + caName;
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removePublisherFromCa(publisherName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    }

  }

  @Command(scope = "ca", name = "ca-rm", description = "remove CA")
  @Service
  public static class CaRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "CA " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCa(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "careq-add", description = "add requestor to CA")
  @Service
  public static class CareqAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String requestorName;

    @Option(name = "--ra", description = "whether as RA")
    @Completion(Completers.YesNoCompleter.class)
    private String raS = "no";

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", multiValued = true,
        description = "profile name or 'all' for all profiles")
    @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
      boolean ra = isEnabled(raS, false, "ra");

      MgmtEntry.CaHasRequestor entry =
          new MgmtEntry.CaHasRequestor(new NameId(null, requestorName));
      entry.setRa(ra);
      entry.setProfiles(profiles);
      int intPermission = ShellUtil.getPermission(permissions);
      entry.setPermission(intPermission);

      String msg = "requestor " + requestorName + " to CA " + caName;
      try {
        caManager.addRequestorToCa(entry, caName);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "careq-info", description = "show information of requestor in CA")
  @Service
  public static class CareqInfo extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (caManager.getCa(caName) == null) {
        throw new CmdFailure("could not find CA '" + caName + "'");
      }

      StringBuilder sb = new StringBuilder();

      Set<MgmtEntry.CaHasRequestor> entries = caManager.getRequestorsForCa(caName);
      if (isNotEmpty(entries)) {
        sb.append("requestors trusted by CA " + caName).append("\n");
        for (MgmtEntry.CaHasRequestor entry : entries) {
          sb.append("----------\n").append(entry).append("\n");
        }
      } else {
        sb.append("no requestor for CA " + caName + " is configured");
      }
      println(sb.toString());
      return null;
    }

  }

  @Command(scope = "ca", name = "careq-rm", description = "remove requestor from CA")
  @Service
  public static class CareqRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--requestor", required = true, multiValued = true,
        description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private List<String> requestorNames;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      for (String requestorName : requestorNames) {
        String msg = "requestor " + requestorName + " from CA " + caName;
        if (force || confirm("Do you want to remove " + msg, 3)) {
          try {
            caManager.removeRequestorFromCa(requestorName, caName);
            println("removed " + msg);
          } catch (CaMgmtException ex) {
            throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
          }
        }
      }

      return null;
    }

  }

  @Command(scope = "ca", name = "ca-revoke", description = "revoke CA")
  @Service
  public static class CaRevoke extends CaAction {

    public static final List<CrlReason> PERMITTED_REASONS = Collections.unmodifiableList(
        Arrays.asList(new CrlReason[] {
          CrlReason.UNSPECIFIED, CrlReason.KEY_COMPROMISE, CrlReason.CA_COMPROMISE,
          CrlReason.AFFILIATION_CHANGED, CrlReason.SUPERSEDED, CrlReason.CESSATION_OF_OPERATION,
          CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN}));

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--reason", required = true, description = "CRL reason")
    @Completion(CaCompleters.CaCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--rev-date", valueToShowInHelp = "current time",
        description = "revocation date, UTC time of format yyyyMMddHHmmss")
    private String revocationDateS;

    @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!PERMITTED_REASONS.contains(crlReason)) {
        throw new IllegalCmdParamException("reason " + reason + " is not permitted");
      }

      if (!caManager.getCaNames().contains(caName)) {
        throw new IllegalCmdParamException("invalid CA name " + caName);
      }

      Date revocationDate = null;
      revocationDate = isNotBlank(revocationDateS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(revocationDateS) : new Date();

      Date invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      CertRevocationInfo revInfo =
          new CertRevocationInfo(crlReason, revocationDate, invalidityDate);
      String msg = "CA " + caName;
      try {
        caManager.revokeCa(caName, revInfo);
        println("revoked " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not revoke " + msg + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  }

  @Command(scope = "ca", name = "ca-unrevoke", description = "unrevoke CA")
  @Service
  public static class CaUnrevoke extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    protected Object execute0() throws Exception {
      if (!caManager.getCaNames().contains(caName)) {
        throw new IllegalCmdParamException("invalid CA name " + caName);
      }

      String msg = "CA " + caName;
      try {
        caManager.unrevokeCa(caName);
        println("unrevoked " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not unrevoke " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "ca-up", description = "update CA")
  @Service
  public static class CaUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--sn-bitlen",
        description = "number of bits of the serial number, between "
            + CaManager.MIN_SERIALNUMBER_SIZE + " and " + CaManager.MAX_SERIALNUMBER_SIZE)
    private Integer snBitLen;

    @Option(name = "--status", description = "CA status")
    @Completion(CaCompleters.CaStatusCompleter.class)
    private String caStatus;

    @Option(name = "--ca-cert-uri", multiValued = true, description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI or 'null'")
    private List<String> ocspUris;

    @Option(name = "--crl-uri", multiValued = true,
        description = "CRL distribution point URI or 'null'")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri", multiValued = true,
        description = "delta CRL distribution point URI or 'null'")
    private List<String> deltaCrlUris;

    @Option(name = "--permission", multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--max-validity", description = "maximal validity")
    private String maxValidity;

    @Option(name = "--expiration-period",
        description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod;

    @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
    private Integer keepExpiredCertInDays;

    @Option(name = "--crl-signer", description = "CRL signer name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String crlSignerName;

    @Option(name = "--precert-signer", description = "Precert (for CT Log) signer name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String precertSignerName;

    @Option(name = "--cmp-responder", description = "CMP responder name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String cmpResponderName;

    @Option(name = "--scep-responder", description = "SCEP responder name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String scepResponderName;

    @Option(name = "--cmp-control", description = "CMP control or 'null'")
    private String cmpControl;

    @Option(name = "--crl-control", description = "CRL control or 'null'")
    private String crlControl;

    @Option(name = "--scep-control", description = "SCEP control or 'null'")
    private String scepControl;

    @Option(name = "--ctlog-control", description = "CT log control")
    private String ctLogControl;

    @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
    private Integer numCrls;

    @Option(name = "--cert", description = "CA certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--certchain", multiValued = true,
        description = "certificate chain of CA certificate")
    @Completion(FileCompleter.class)
    private List<String> issuerCertFiles;

    @Option(name = "--signer-type", description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf", description = "CA signer configuration or 'null'")
    private String signerConf;

    @Option(name = "--duplicate-key", description = "whether duplicate key is permitted")
    @Completion(Completers.YesNoCompleter.class)
    private String duplicateKeyS;

    @Option(name = "--duplicate-subject", description = "whether duplicate subject is permitted")
    @Completion(Completers.YesNoCompleter.class)
    private String duplicateSubjectS;

    @Option(name = "--support-cmp", description = "whether the CMP protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportCmpS;

    @Option(name = "--support-rest", description = "whether the REST protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportRestS;

    @Option(name = "--support-scep", description = "whether the SCEP protocol is supported")
    @Completion(Completers.YesNoCompleter.class)
    private String supportScepS;

    @Option(name = "--save-req", description = "whether the request is saved")
    @Completion(Completers.YesNoCompleter.class)
    private String saveReqS;

    @Option(name = "--validity-mode", description = "mode of valditity")
    @Completion(CaCompleters.ValidityModeCompleter.class)
    private String validityModeS;

    @Option(name = "--extra-control", description = "extra control")
    private String extraControl;

    @Reference
    private PasswordResolver passwordResolver;

    protected MgmtEntry.ChangeCa getChangeCaEntry() throws Exception {
      MgmtEntry.ChangeCa entry = new MgmtEntry.ChangeCa(new NameId(null, caName));

      if (snBitLen != null) {
        Args.range(snBitLen, "sn-bitlen",
            CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
        entry.setSerialNoBitLen(snBitLen);
      }

      if (caStatus != null) {
        entry.setStatus(CaStatus.forName(caStatus));
      }

      if (expirationPeriod != null && expirationPeriod < 0) {
        throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
      } else {
        entry.setExpirationPeriod(expirationPeriod);
      }

      if (keepExpiredCertInDays != null) {
        entry.setKeepExpiredCertInDays(keepExpiredCertInDays);
      }

      if (certFile != null) {
        entry.setEncodedCert(IoUtil.read(certFile));
      }

      if (CollectionUtil.isNonEmpty(issuerCertFiles)) {
        List<byte[]> list = new ArrayList<>(issuerCertFiles.size());
        for (String m : issuerCertFiles) {
          if (CaManager.NULL.equalsIgnoreCase(m)) {
            list.clear();
            break;
          }

          list.add(X509Util.parseCert(Paths.get(m).toFile()).getEncoded());
        }
        entry.setEncodedCertchain(list);
      }

      if (signerConf != null) {
        String tmpSignerType = signerType;
        if (tmpSignerType == null) {
          MgmtEntry.Ca caEntry = caManager.getCa(caName);
          if (caEntry == null) {
            throw new IllegalCmdParamException("please specify the signerType");
          }
          tmpSignerType = caEntry.getSignerType();
        }

        signerConf = ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf,
            passwordResolver, securityFactory);
        entry.setSignerConf(signerConf);
      }

      if (duplicateKeyS != null) {
        entry.setDuplicateKeyPermitted(isEnabled(duplicateKeyS, true, "duplicate-key"));
      }

      if (duplicateSubjectS != null) {
        entry.setDuplicateSubjectPermitted(isEnabled(duplicateSubjectS, true, "duplicate-subject"));
      }

      if (supportCmpS != null) {
        entry.setSupportCmp(isEnabled(supportCmpS, false, "support-cmp"));
      }

      if (supportRestS != null) {
        entry.setSupportRest(isEnabled(supportRestS, false, "support-rest"));
      }

      if (supportScepS != null) {
        entry.setSupportScep(isEnabled(supportScepS, false, "support-scep"));
      }

      if (saveReqS != null) {
        entry.setSaveRequest(isEnabled(saveReqS, true, "save-req"));
      }

      if (CollectionUtil.isNonEmpty(permissions)) {
        int intPermission = ShellUtil.getPermission(permissions);
        entry.setPermission(intPermission);
      }

      CaUris caUris = new CaUris(getUris(caCertUris), getUris(ocspUris), getUris(crlUris),
          getUris(deltaCrlUris));
      entry.setCaUris(caUris);

      if (validityModeS != null) {
        ValidityMode validityMode = ValidityMode.forName(validityModeS);
        entry.setValidityMode(validityMode);
      }

      if (maxValidity != null) {
        entry.setMaxValidity(Validity.getInstance(maxValidity));
      }

      if (cmpControl != null) {
        entry.setCmpControl(cmpControl);
      }

      if (crlControl != null) {
        entry.setCrlControl(crlControl);
      }

      if (scepControl != null) {
        entry.setScepControl(scepControl);
      }

      if (ctLogControl != null) {
        entry.setCtLogControl(ctLogControl);
      }

      if (cmpResponderName != null) {
        entry.setCmpResponderName(cmpResponderName);
      }

      if (scepResponderName != null) {
        entry.setScepResponderName(scepResponderName);
      }

      if (crlSignerName != null) {
        entry.setCrlSignerName(crlSignerName);
      }

      if (precertSignerName != null) {
        entry.setPrecertSignerName(precertSignerName);
      }

      if (extraControl != null) {
        entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
      }

      if (numCrls != null) {
        entry.setNumCrls(numCrls);
      }

      return entry;
    } // method getChangeCaEntry

    @Override
    protected Object execute0() throws Exception {
      String msg = "CA " + caName;
      try {
        caManager.changeCa(getChangeCaEntry());
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

    private static List<String> getUris(List<String> uris) {
      if (uris == null) {
        return null;
      }

      boolean clearUris = false;
      for (String uri : uris) {
        if (CaManager.NULL.equalsIgnoreCase(uri)) {
          clearUris = true;
          break;
        }
      }

      return clearUris ? Collections.emptyList() : new ArrayList<>(uris);
    }

  }

  @Command(scope = "ca", name = "causer-add", description = "add user to CA")
  @Service
  public static class CauserAdd extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--user", required = true, description = "user name")
    private String userName;

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--profile", required = true, multiValued = true,
        description = "profile name or 'all' for all profiles")
    @Completion(CaCompleters.ProfileNameAndAllCompleter.class)
    private Set<String> profiles;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.CaHasUser entry = new MgmtEntry.CaHasUser(new NameId(null, userName));
      entry.setProfiles(profiles);
      int intPermission = ShellUtil.getPermission(permissions);
      entry.setPermission(intPermission);

      String msg = "user " + userName + " to CA " + caName;
      try {
        caManager.addUserToCa(entry, caName);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "causer-rm", description = "remove user from CA")
  @Service
  public static class CauserRm extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--user", required = true, description = "user name")
    private String userName;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "user " + userName + " from CA " + caName;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeUserFromCa(userName, caName);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "clear-publishqueue", description = "clear publish queue")
  @Service
  public static class ClearPublishqueue extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name or 'all' for all CAs")
    @Completion(CaCompleters.CaNamePlusAllCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true,
        description = "publisher name or 'all' for all publishers")
    @Completion(CaCompleters.PublisherNamePlusAllCompleter.class)
    private List<String> publisherNames;

    @Override
    protected Object execute0() throws Exception {
      if (publisherNames == null) {
        throw new IllegalStateException("should not reach here");
      }
      boolean allPublishers = false;
      for (String publisherName : publisherNames) {
        if ("all".equalsIgnoreCase(publisherName)) {
          allPublishers = true;
          break;
        }
      }

      if (allPublishers) {
        publisherNames = null;
      }

      if ("all".equalsIgnoreCase(caName)) {
        caName = null;
      }

      String msg = "publish queue of CA " + caName + " for publishers " + toString(publisherNames);
      try {
        caManager.clearPublishQueue(caName, publisherNames);
        println("cleared " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not clear " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "export-conf", description = "export configuration to zip file")
  @Service
  public static class ExportConf extends CaAction {

    @Option(name = "--conf-file", required = true,
        description = "zip file that saves the exported configuration")
    @Completion(FileCompleter.class)
    private String confFile;

    @Option(name = "--ca", multiValued = true,
        description = "CAs whose configuration should be exported. Empty list means all CAs")
    @Completion(CaCompleters.CaNameCompleter.class)
    private List<String> caNames;

    @Override
    protected Object execute0() throws Exception {
      String msg = "configuration to file " + confFile;
      try {
        InputStream is = caManager.exportConf(caNames);
        save(new File(confFile), IoUtil.read(is));
        println("exported " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not export " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "load-conf", description = "load configuration")
  @Service
  public static class LoadConf extends CaAction {

    @Option(name = "--conf-file", description = "CA system configuration file (XML or zip file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Option(name = "--outform", description = "output format of the root certificates")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out-dir",
        description = "directory to save the root certificates")
    @Completion(FileCompleter.class)
    private String outDir = ".";

    @Override
    protected Object execute0() throws Exception {
      String msg = "configuration " + confFile;
      try {
        InputStream confStream;
        if (confFile.endsWith(".json")) {
          confStream = CaConfs.convertFileConfToZip(confFile);
        } else {
          confStream = Files.newInputStream(Paths.get(confFile));
        }

        Map<String, X509Certificate> rootCerts = caManager.loadConf(confStream);
        if (CollectionUtil.isEmpty(rootCerts)) {
          println("loaded " + msg);
        } else {
          println("loaded " + msg);
          for (String caname : rootCerts.keySet()) {
            String filename = "ca-" + caname + "." + outform.toLowerCase();
            saveVerbose("saved certificate of root CA " + caname + " to",
                new File(outDir, filename),
                encodeCrl(rootCerts.get(caname).getEncoded(), outform));
          }
        }
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not load " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "notify-change", description = "notify the change of CA system")
  @Service
  public static class NotifyChange extends CaAction {

    @Override
    protected Object execute0() throws Exception {
      String msg = "the change of CA system";
      try {
        caManager.notifyCaChange();
        println("notified " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not notify " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "profile-add", description = "add certificate profile")
  @Service
  public static class ProfileAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    private String name;

    @Option(name = "--type", required = true, description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    private String type;

    @Option(name = "--conf", description = "certificate profile configuration")
    private String conf;

    @Option(name = "--conf-file", description = "certificate profile configuration file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (conf == null && confFile != null) {
        conf = new String(IoUtil.read(confFile));
      }

      MgmtEntry.Certprofile entry = new MgmtEntry.Certprofile(new NameId(null, name), type, conf);
      String msg = "certificate profile " + name;
      try {
        caManager.addCertprofile(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "profile-export",
      description = "export certificate profile configuration")
  @Service
  public static class ProfileExport extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the profile configuration")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.Certprofile entry = caManager.getCertprofile(name);
      if (entry == null) {
        throw new IllegalCmdParamException("no certificate profile named " + name + " is defined");
      }

      if (StringUtil.isBlank(entry.getConf())) {
        println("cert profile does not have conf");
      } else {
        saveVerbose("saved cert profile configuration to", confFile,
            StringUtil.toUtf8Bytes(entry.getConf()));
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "profile-info",
      description = "show information of certificate profile")
  @Service
  public static class ProfileInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
        description = "show certificate profile information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getCertprofileNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1");
          sb.append(" profile is configured\n");
        } else {
          sb.append(size).append(" profiles are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        MgmtEntry.Certprofile entry = caManager.getCertprofile(name);
        if (entry == null) {
          throw new CmdFailure("\tno certificate profile named '" + name + "' is configured");
        } else {
          sb.append(entry.toString(verbose));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "profile-rm", description = "remove certificate profile")
  @Service
  public static class ProfileRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "certificate profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "certificate profile " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCertprofile(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "profile-up", description = "update certificate profile")
  @Service
  public static class ProfileUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "profile type")
    @Completion(CaCompleters.ProfileTypeCompleter.class)
    protected String type;

    @Option(name = "--conf", description = "certificate profile configuration or 'null'")
    protected String conf;

    @Option(name = "--conf-file", description = "certificate profile configuration file")
    @Completion(FileCompleter.class)
    protected String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (type == null && conf == null && confFile == null) {
        throw new IllegalCmdParamException("nothing to update");
      }

      if (conf == null && confFile != null) {
        conf = new String(IoUtil.read(confFile));
      }

      String msg = "certificate profile " + name;
      try {
        caManager.changeCertprofile(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "publisher-add", description = "add publisher")
  @Service
  public static class PublisherAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher Name")
    private String name;

    @Option(name = "--type", required = true, description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    private String type;

    @Option(name = "--conf", description = "publisher configuration")
    private String conf;

    @Option(name = "--conf-file", description = "publisher configuration file")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (conf == null && confFile != null) {
        conf = new String(IoUtil.read(confFile));
      }

      MgmtEntry.Publisher entry = new MgmtEntry.Publisher(new NameId(null, name), type, conf);
      String msg = "publisher " + name;
      try {
        caManager.addPublisher(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "publisher-export", description = "export publisher configuration")
  @Service
  public static class PublisherExport extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the publisher configuration")
    @Completion(FileCompleter.class)
    private String confFile;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.Publisher entry = caManager.getPublisher(name);
      if (entry == null) {
        throw new IllegalCmdParamException("no publisher named " + name + " is defined");
      }

      if (StringUtil.isBlank(entry.getConf())) {
        println("publisher does not have conf");
      } else {
        saveVerbose("saved publisher configuration to", confFile,
            StringUtil.toUtf8Bytes(entry.getConf()));
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "publisher-info", description = "show information of publisher")
  @Service
  public static class PublisherInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Override
    protected Object execute0() throws Exception {
      if (name == null) {
        Set<String> names = caManager.getPublisherNames();
        int size = names.size();

        StringBuilder sb = new StringBuilder();
        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1");
          sb.append(" publisher is configured\n");
        } else {
          sb.append(size).append(" publishers are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
        println(sb.toString());
      } else {
        MgmtEntry.Publisher entry = caManager.getPublisher(name);
        if (entry == null) {
          throw new CmdFailure("\tno publisher named '" + name + "' is configured");
        } else {
          println(entry.toString());
        }
      }

      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "publisher-rm", description = "remove publisher")
  @Service
  public static class PublisherRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "publisher " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removePublisher(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "publisher-up", description = "update publisher")
  @Service
  public static class PublisherUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "publisher name")
    @Completion(CaCompleters.PublisherNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "publisher type")
    @Completion(CaCompleters.PublisherTypeCompleter.class)
    protected String type;

    @Option(name = "--conf", description = "publisher configuration or 'null'")
    protected String conf;

    @Option(name = "--conf-file", description = "profile configuration file")
    @Completion(FileCompleter.class)
    protected String confFile;

    @Override
    protected Object execute0() throws Exception {
      if (type == null && conf == null && confFile == null) {
        throw new IllegalCmdParamException("nothing to update");
      }

      if (conf == null && confFile != null) {
        conf = new String(IoUtil.read(confFile));
      }

      String msg = "publisher " + name;
      try {
        caManager.changePublisher(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "refresh-token", description = "refresh token for signers")
  @Service
  public static class RefreshToken extends CaAction {

    @Option(name = "--type", required = true, description = "type of the signer")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    protected String type;

    @Override
    protected Object execute0() throws Exception {
      caManager.refreshTokenForSignerType(type);
      println("refreshed token for signer type " + type);
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "republish", description = "republish certificates")
  @Service
  public static class Republish extends CaAction {

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--publisher", required = true, multiValued = true,
        description = "publisher name or 'all' for all publishers")
    @Completion(CaCompleters.PublisherNamePlusAllCompleter.class)
    private List<String> publisherNames;

    @Override
    protected Object execute0() throws Exception {
      if (publisherNames == null) {
        throw new IllegalStateException("should not reach here");
      }
      boolean allPublishers = false;
      for (String publisherName : publisherNames) {
        if ("all".equalsIgnoreCase(publisherName)) {
          allPublishers = true;
          break;
        }
      }

      if (allPublishers) {
        publisherNames = null;
      }

      if ("all".equalsIgnoreCase(caName)) {
        caName = null;
      }

      String msg = "certificates";
      try {
        caManager.republishCertificates(caName, publisherNames, numThreads);
        println("republished " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not republish " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "requestor-add", description = "add requestor")
  @Service
  public static class RequestorAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "requestor name")
    private String name;

    @Option(name = "--cert", description = "requestor certificate file\n"
        + "(exactly one of cert and password must be specified).")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--password", description = "Passord for PBM (Password based MAC)")
    private String password;

    @Override
    protected Object execute0() throws Exception {
      if (!(certFile == null ^ password == null)) {
        throw new CmdFailure("exactly one of cert and password must be specified");
      }

      MgmtEntry.Requestor entry;
      if (certFile != null) {
        X509Certificate cert = X509Util.parseCert(IoUtil.read(certFile));
        entry = new MgmtEntry.Requestor(new NameId(null, name), MgmtEntry.Requestor.TYPE_CERT,
            Base64.encodeToString(cert.getEncoded()));
      } else {
        entry = new MgmtEntry.Requestor(
                  new NameId(null, name), MgmtEntry.Requestor.TYPE_PBM, password);
        String keyId = HashAlgo.SHA1.hexHash(StringUtil.toUtf8Bytes(entry.getIdent().getName()));
        println("The key ID is " + keyId);
      }

      String msg = "CMP requestor " + name;

      try {
        caManager.addRequestor(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "requestor-info", description = "show information of requestor")
  @Service
  public static class RequestorInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v",
        description = "show requestor information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getRequestorNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1");
          sb.append(" CMP requestor is configured\n");
        } else {
          sb.append(size).append(" CMP requestors are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        MgmtEntry.Requestor entry = caManager.getRequestor(name);
        if (entry == null) {
          throw new CmdFailure("could not find CMP requestor '" + name + "'");
        } else {
          sb.append(entry.toString(verbose.booleanValue()));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "requestor-rm", description = "remove requestor")
  @Service
  public static class RequestorRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "CMP requestor " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeRequestor(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "requestor-up", description = "update requestor")
  @Service
  public static class RequestorUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "requestor name")
    @Completion(CaCompleters.RequestorNameCompleter.class)
    protected String name;

    @Option(name = "--cert", description = "requestor certificate file\n"
        + "(exactly one of cert and password must be specified).")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--password", description = "Passord for PBM (Password based MAC)")
    protected String password;

    @Override
    protected Object execute0() throws Exception {
      // check if the certificate is valid
      byte[] certBytes = IoUtil.read(certFile);
      X509Util.parseCert(new ByteArrayInputStream(certBytes));
      String msg = "CMP requestor " + name;

      String type;
      String conf;
      if (certFile != null) {
        type = MgmtEntry.Requestor.TYPE_CERT;
        X509Certificate cert = X509Util.parseCert(IoUtil.read(certFile));
        conf = Base64.encodeToString(cert.getEncoded());
      } else {
        type = MgmtEntry.Requestor.TYPE_PBM;
        conf = password;
      }

      try {
        caManager.changeRequestor(name, type, conf);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "restart", description = "restart CA system")
  @Service
  public static class Restart extends CaAction {

    @Override
    protected Object execute0() throws Exception {
      try {
        caManager.restartCaSystem();
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not restart CA system, error: " + ex.getMessage(), ex);
      }

      StringBuilder sb = new StringBuilder("restarted CA system\n");

      sb.append("  successful CAs:\n");
      String prefix = "    ";
      printCaNames(sb, caManager.getSuccessfulCaNames(), prefix);

      sb.append("  failed CAs:\n");
      printCaNames(sb, caManager.getFailedCaNames(), prefix);

      sb.append("  inactive CAs:\n");
      printCaNames(sb, caManager.getInactiveCaNames(), prefix);

      print(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "signer-add", description = "add signer")
  @Service
  public static class SignerAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
    private String name;

    @Option(name = "--type", required = true, description = "type of the signer")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String type;

    @Option(name = "--conf", required = true, description = "conf of the signer")
    private String conf;

    @Option(name = "--cert", description = "signer certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Reference
    private PasswordResolver passwordResolver;

    @Override
    protected Object execute0() throws Exception {
      String base64Cert = null;
      X509Certificate signerCert = null;
      if (certFile != null) {
        signerCert = X509Util.parseCert(new File(certFile));
        base64Cert = IoUtil.base64Encode(signerCert.getEncoded(), false);
      }

      if ("PKCS12".equalsIgnoreCase(type) || "JKS".equalsIgnoreCase(type)) {
        conf = ShellUtil.canonicalizeSignerConf(type, conf, passwordResolver, securityFactory);
      }
      MgmtEntry.Signer entry = new MgmtEntry.Signer(name, type, conf, base64Cert);

      String msg = "signer " + name;
      try {
        caManager.addSigner(entry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "signer-info", description = "show information of signer")
  @Service
  public static class SignerInfo extends CaAction {

    @Argument(index = 0, name = "name", description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(name = "--verbose", aliases = "-v", description = "show signer information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      StringBuilder sb = new StringBuilder();

      if (name == null) {
        Set<String> names = caManager.getSignerNames();
        int size = names.size();

        if (size == 0 || size == 1) {
          sb.append((size == 0) ? "no" : "1").append(" signer is configured\n");
        } else {
          sb.append(size).append(" signers are configured:\n");
        }

        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);

        for (String entry : sorted) {
          sb.append("\t").append(entry).append("\n");
        }
      } else {
        MgmtEntry.Signer entry = caManager.getSigner(name);
        if (entry == null) {
          throw new CmdFailure("could not find signer " + name);
        } else {
          sb.append(entry.toString(verbose));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  }

  @Command(scope = "ca", name = "signer-rm", description = "remove signer")
  @Service
  public static class SignerRm extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "signer " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeSigner(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "signer-up", description = "update signer")
  @Service
  public static class SignerUp extends CaAction {

    @Reference
    protected PasswordResolver passwordResolver;

    @Option(name = "--name", aliases = "-n", required = true, description = "signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    protected String name;

    @Option(name = "--type", description = "type of the signer")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    protected String type;

    @Option(name = "--cert", description = "certificate file or 'null'")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--conf", description = "conf of the signer or 'null'")
    private String conf;

    protected String getSignerConf() throws Exception {
      if (conf == null) {
        return null;
      }
      String tmpType = type;
      if (tmpType == null) {
        MgmtEntry.Signer entry = caManager.getSigner(name);
        if (entry == null) {
          throw new IllegalCmdParamException("please specify the type");
        }
        tmpType = entry.getType();
      }

      return ShellUtil.canonicalizeSignerConf(tmpType, conf, passwordResolver, securityFactory);
    }

    @Override
    protected Object execute0() throws Exception {
      String cert = null;
      if (CaManager.NULL.equalsIgnoreCase(certFile)) {
        cert = CaManager.NULL;
      } else if (certFile != null) {
        Certificate bcCert = X509Util.parseBcCert(new File(certFile));
        byte[] certBytes = bcCert.getEncoded();
        cert = Base64.encodeToString(certBytes);
      }

      String msg = "signer " + name;
      try {
        caManager.changeSigner(name, type, getSignerConf(), cert);
        println("updated " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "system-status", description = "show CA system status")
  @Service
  public static class SystemStatus extends CaAction {

    @Override
    protected Object execute0() throws Exception {
      CaSystemStatus status = caManager.getCaSystemStatus();
      if (status != null) {
        println(status.toString());
      } else {
        throw new CmdFailure("status is null");
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "unlock", description = "unlock CA system")
  @Service
  public static class Unlock extends CaAction {

    @Override
    protected Object execute0() throws Exception {
      try {
        caManager.unlockCa();
        println("unlocked CA system, calling ca:restart to restart CA system");
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not unlock CA system, error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "user-add", description = "add user")
  @Service
  public static class UserAdd extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--password", description = "user password")
    private String password;

    @Option(name = "--inactive", description = "do not activate this user")
    private Boolean inactive = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (password == null) {
        password = new String(readPassword());
      }
      MgmtEntry.AddUser userEntry =
          new MgmtEntry.AddUser(new NameId(null, name), !inactive, password);
      String msg = "user " + name;
      try {
        caManager.addUser(userEntry);
        println("added " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not add " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "user-info", description = "show information of user")
  @Service
  public static class UserInfo extends CaAction {

    @Argument(index = 0, name = "name", required = true, description = "user name")
    private String name;

    @Override
    protected Object execute0() throws Exception {
      MgmtEntry.User userEntry = caManager.getUser(name);
      if (userEntry == null) {
        throw new CmdFailure("no user named '" + name + "' is configured");
      }

      StringBuilder sb = new StringBuilder();
      sb.append(userEntry);

      Map<String, MgmtEntry.CaHasUser> caHasUsers = caManager.getCaHasUsersForUser(name);
      for (String ca : caHasUsers.keySet()) {
        MgmtEntry.CaHasUser entry = caHasUsers.get(ca);
        sb.append("\n----- CA ").append(ca).append("-----");
        sb.append("\nprofiles: ").append(entry.getProfiles());
        sb.append("\npermission: ").append(
            PermissionConstants.permissionToString(entry.getPermission()));
      }
      println(sb.toString());
      return null;
    }

  }

  @Command(scope = "ca", name = "user-rm", description = "remove user")
  @Service
  public static class UserRm extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      String msg = "user " + name;
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeUser(name);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "user-up", description = "update user")
  @Service
  public static class UserUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "user Name")
    private String name;

    @Option(name = "--active", description = "activate this user")
    private Boolean active;

    @Option(name = "--inactive", description = "deactivate this user")
    private Boolean inactive;

    @Option(name = "--password", description = "user password, 'CONSOLE' to read from console")
    private String password;

    @Override
    protected Object execute0() throws Exception {
      Boolean realActive;
      if (active != null) {
        if (inactive != null) {
          throw new IllegalCmdParamException("maximal one of --active and --inactive can be set");
        }
        realActive = Boolean.TRUE;
      } else if (inactive != null) {
        realActive = Boolean.FALSE;
      } else {
        realActive = null;
      }

      MgmtEntry.ChangeUser entry = new MgmtEntry.ChangeUser(new NameId(null, name));
      if (realActive != null) {
        entry.setActive(realActive);
      }

      if ("CONSOLE".equalsIgnoreCase(password)) {
        password = new String(readPassword());
      }

      if (password != null) {
        entry.setPassword(password);
      }

      String msg = "user " + name;
      try {
        caManager.changeUser(entry);
        println("changed " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not change " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

}
