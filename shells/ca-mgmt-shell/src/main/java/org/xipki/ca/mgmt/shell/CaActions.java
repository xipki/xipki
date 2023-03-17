// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.SecurityFactory;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.*;

import java.io.File;
import java.nio.file.Paths;
import java.util.*;

/**
 * Actions to manage CA.
 *
 * @author Lijun Liao
 *
 */
public class CaActions {

  public abstract static class CaAction extends XiAction {

    @Reference
    protected CaManager caManager;

    @Reference
    protected SecurityFactory securityFactory;

    protected static Date parseDate(String dateStr) {
      return StringUtil.isBlank(dateStr) ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(dateStr);
    }

    protected static String toString(Collection<?> col) {
      if (col == null) {
        return "null";
      }

      StringBuilder sb = new StringBuilder().append("{");
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
    } // method toString

    protected void printCaNames(StringBuilder sb, Set<String> caNames, String prefix)
        throws CaMgmtException {
      if (caNames.isEmpty()) {
        sb.append(prefix).append("-\n");
        return;
      }

      for (String caName : caNames) {
        Set<String> aliases = caManager.getAliasesForCa(caName);
        sb.append(prefix).append(caName);
        if (!CollectionUtil.isEmpty(aliases)) {
          sb.append(" (aliases ").append(aliases).append(")");
        }
        sb.append("\n");
      }
    } // method printCaNames

  } // class CaAction

  @Command(scope = "ca", name = "ca-add", description = "add CA")
  @Service
  public static class CaAdd extends CaAddOrGenAction {

    @Option(name = "--cert", description = "CA certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--certchain", multiValued = true, description = "certificate chain of CA certificate")
    @Completion(FileCompleter.class)
    private List<String> issuerCertFiles;

    @Override
    protected Object execute0() throws Exception {
      CaEntry caEntry = getCaEntry();
      if (certFile != null) {
        caEntry.setCert(X509Util.parseCert(new File(certFile)));
      }

      if (CollectionUtil.isNotEmpty(issuerCertFiles)) {
        List<X509Cert> list = new ArrayList<>(issuerCertFiles.size());
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
    } // method execute0

  } // class CaAdd

  public abstract static class CaAddOrGenAction extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "CA name")
    private String caName;

    @Option(name = "--status", description = "CA status")
    @Completion(CaCompleters.CaStatusCompleter.class)
    private String caStatus = "active";

    @Option(name = "--ca-cert-uri", multiValued = true, description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI")
    private List<String> ocspUris;

    @Option(name = "--crl-uri", multiValued = true, description = "CRL distribution point")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri", multiValued = true, description = "Delta CRL distribution point")
    private List<String> deltaCrlUris;

    @Option(name = "--permission", required = true, multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--sn-len", description = "number of bytes of the serial number, between "
            + CaManager.MIN_SERIALNUMBER_SIZE + " and " + CaManager.MAX_SERIALNUMBER_SIZE)
    private int snLen = CaManager.MAX_SERIALNUMBER_SIZE;

    @Option(name = "--next-crl-no", required = true, description = "CRL number for the next CRL")
    private Long nextCrlNumber;

    @Option(name = "--max-validity", required = true, description = "maximal validity")
    private String maxValidity;

    @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
    private Integer keepExpiredCertInDays = -1;

    @Option(name = "--crl-signer", description = "CRL signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    private String crlSignerName;

    @Option(name = "--keypair-gen", multiValued = true, description = "(ordered) keypair generation names")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private List<String> keypairGenNames;

    @Option(name = "--crl-control", description = "CRL control")
    private String crlControl;

    @Option(name = "--ctlog-control", description = "CT log control")
    private String ctlogControl;

    @Option(name = "--revoke-suspended-control",
        description = "Revoke suspended certificates control")
    private String revokeSuspendedControl;

    @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
    private Integer numCrls = 30;

    @Option(name = "--expiration-period", description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod = 365;

    @Option(name = "--signer-type", required = true, description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf", required = true, description = "CA signer configuration")
    private String signerConf;

    @Option(name = "--save-cert", description = "whether to save the certificate")
    @Completion(Completers.YesNoCompleter.class)
    private String saveCertS = "yes";

    @Option(name = "--save-keypair", description = "whether to save the keypair generated by the CA")
    @Completion(Completers.YesNoCompleter.class)
    private String saveKeypairS = "no";

    @Option(name = "--unique-key", description = "whether to require unique public keys")
    @Completion(Completers.YesNoCompleter.class)
    private String uniqueKeyS = "yes";

    @Option(name = "--validity-mode", description = "mode of valditity")
    @Completion(CaCompleters.ValidityModeCompleter.class)
    private String validityModeS = "STRICT";

    @Option(name = "--extra-control", description = "extra control")
    private String extraControl;

    protected CaEntry getCaEntry() throws Exception {
      Args.range(snLen, "snLen", CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);

      if (nextCrlNumber < 1) {
        throw new IllegalCmdParamException("invalid CRL number: " + nextCrlNumber);
      }

      if (numCrls < 0) {
        throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
      }

      if (expirationPeriod < 0) {
        throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
      }

      if (StringUtil.orEqualsIgnoreCase(signerType, "PKCS12", "JCEKS")) {
        signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, securityFactory);
      }

      CaUris caUris = new CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
      CaEntry entry = new CaEntry(new NameId(null, caName), snLen, nextCrlNumber,
          signerType, signerConf, caUris, numCrls, expirationPeriod);

      entry.setKeepExpiredCertInDays(keepExpiredCertInDays);
      entry.setSaveCert(isEnabled(saveCertS, true, "save-cert"));
      entry.setSaveKeypair(isEnabled(saveKeypairS, false, "save-keypair"));
      entry.setUniqueKey(isEnabled(uniqueKeyS, false, "unique-key"));
      entry.setValidityMode(ValidityMode.forName(validityModeS));
      entry.setStatus(CaStatus.forName(caStatus));

      if (crlControl != null) {
        entry.setCrlControl(new CrlControl(crlControl));
      }

      if (ctlogControl != null) {
        entry.setCtlogControl(new CtlogControl(ctlogControl));
      }

      if (revokeSuspendedControl != null) {
        entry.setRevokeSuspendedControl(new RevokeSuspendedControl(new ConfPairs(revokeSuspendedControl)));
      }

      if (crlSignerName != null) {
        entry.setCrlSignerName(crlSignerName);
      }

      if (CollectionUtil.isNotEmpty(keypairGenNames)) {
        entry.setKeypairGenNames(keypairGenNames);
      }

      entry.setMaxValidity(Validity.getInstance(maxValidity));
      entry.setKeepExpiredCertInDays(keepExpiredCertInDays);
      entry.setPermission(ShellUtil.getPermission(permissions));

      if (extraControl != null) {
        extraControl = extraControl.trim();
      }
      if (StringUtil.isNotBlank(extraControl)) {
        entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
      }
      return entry;
    } // method getCaEntry

  } // class CaAddOrGenAction

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
    } // method execute0

  } // class CaaliasAdd

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
          sb.append((size == 0) ? "no" : "1").append(" CA alias is configured\n");
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
          sb.append(caAlias).append("\n\t").append(caManager.getCaNameForAlias(caAlias));
        } else {
          throw new CmdFailure("could not find CA alias '" + caAlias + "'");
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class CaaliasInfo

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
    } // method execute0

  } // class CaaliasRm

  @Command(scope = "ca", name = "gen-rootca", description = "generate selfsigned CA")
  @Service
  public static class GenRootca extends CaAddOrGenAction {

    @Option(name = "--subject", required = true, description = "subject of the Root CA")
    private String subject;

    @Option(name = "--profile", required = true, description = "profile of the Root CA")
    private String rootcaProfile;

    @Option(name = "--serial", description = "serial number of the Root CA")
    private String serialS;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", description = "where to save the generated CA certificate")
    @Completion(FileCompleter.class)
    private String rootcaCertOutFile;

    @Override
    protected Object execute0() throws Exception {
      CaEntry caEntry = getCaEntry();
      Date notBefore = parseDate(notBeforeS);
      Date notAfter = parseDate(notAfterS);
      X509Cert rootcaCert = caManager.generateRootCa(caEntry, rootcaProfile, subject, serialS, notBefore, notAfter);
      if (rootcaCertOutFile != null) {
        saveVerbose("saved root certificate to file", rootcaCertOutFile,
            encodeCert(rootcaCert.getEncoded(), outform));
      }
      println("generated root CA " + caEntry.getIdent().getName());
      return null;
    } // method execute0

  } // class GenRootca

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
        CaEntry entry = caManager.getCa(name);
        if (entry == null) {
          throw new CmdFailure("could not find CA '" + name + "'");
        } else {
          if (CaStatus.ACTIVE == entry.getStatus()) {
            boolean started = caManager.getSuccessfulCaNames().contains(entry.getIdent().getName());
            sb.append("started: ").append(started).append("\n");
          }
          Set<String> aliases = caManager.getAliasesForCa(name);
          sb.append("aliases: ").append(toString(aliases)).append("\n").append(entry.toString(verbose));
        }
      }

      println(sb.toString());
      return null;
    } // method execute0

  } // class CaInfo

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
    } // method execute0

  } // class CaRm

  @Command(scope = "ca", name = "ca-revoke", description = "revoke CA")
  @Service
  public static class CaRevoke extends CaAction {

    public static final List<CrlReason> PERMITTED_REASONS = Collections.unmodifiableList(
        Arrays.asList(CrlReason.UNSPECIFIED, CrlReason.KEY_COMPROMISE, CrlReason.CA_COMPROMISE,
            CrlReason.AFFILIATION_CHANGED, CrlReason.SUPERSEDED, CrlReason.CESSATION_OF_OPERATION,
            CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN));

    @Argument(index = 0, name = "name", description = "CA name", required = true)
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--reason", required = true, description = "CRL reason")
    @Completion(CaCompleters.CaCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--rev-date", description = "revocation date, UTC time of format yyyyMMddHHmmss")
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

      Date revocationDate = isNotBlank(revocationDateS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(revocationDateS) : new Date();

      Date invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      try {
        caManager.revokeCa(caName, new CertRevocationInfo(crlReason, revocationDate, invalidityDate));
        println("revoked CA " + caName);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not revoke CA " + caName + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class CaRevoke

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

      try {
        caManager.unrevokeCa(caName);
        println("unrevoked CA " + caName);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not unrevoke CA " + caName + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

  } // class CaUnrevoke

  @Command(scope = "ca", name = "ca-up", description = "update CA")
  @Service
  public static class CaUp extends CaAction {

    @Option(name = "--name", aliases = "-n", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--sn-len", description = "number of octets of the serial number, between "
            + CaManager.MIN_SERIALNUMBER_SIZE + " and " + CaManager.MAX_SERIALNUMBER_SIZE)
    private Integer snLen;

    @Option(name = "--status", description = "CA status")
    @Completion(CaCompleters.CaStatusCompleter.class)
    private String caStatus;

    @Option(name = "--ca-cert-uri", multiValued = true, description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI or 'null'")
    private List<String> ocspUris;

    @Option(name = "--crl-uri", multiValued = true, description = "CRL distribution point URI or 'null'")
    private List<String> crlUris;

    @Option(name = "--deltacrl-uri", multiValued = true, description = "delta CRL distribution point URI or 'null'")
    private List<String> deltaCrlUris;

    @Option(name = "--permission", multiValued = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private Set<String> permissions;

    @Option(name = "--max-validity", description = "maximal validity")
    private String maxValidity;

    @Option(name = "--expiration-period", description = "days before expiration time of CA to issue certificates")
    private Integer expirationPeriod;

    @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
    private Integer keepExpiredCertInDays;

    @Option(name = "--crl-signer", description = "CRL signer name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String crlSignerName;

    @Option(name = "--keypair-gen", multiValued = true, description = "(ordered) Keypair generation name or 'null")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private List<String> keypairGenNames;

    @Option(name = "--crl-control", description = "CRL control or 'null'")
    private String crlControl;

    @Option(name = "--ctlog-control", description = "CT log control")
    private String ctlogControl;

    @Option(name = "--revoke-suspended-control", description = "Revoke suspended certificates control")
    private String revokeSuspendedControl;

    @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
    private Integer numCrls;

    @Option(name = "--cert", description = "CA certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Option(name = "--certchain", multiValued = true, description = "certificate chain of CA certificate")
    @Completion(FileCompleter.class)
    private List<String> issuerCertFiles;

    @Option(name = "--signer-type", description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(name = "--signer-conf", description = "CA signer configuration or 'null'")
    private String signerConf;

    @Option(name = "--save-cert", description = "whether to save the certificate")
    @Completion(Completers.YesNoCompleter.class)
    private String saveCertS;

    @Option(name = "--save-keypair", description = "whether to save the keypair generated by the CA")
    @Completion(Completers.YesNoCompleter.class)
    private String saveKeypairS;

    @Option(name = "--unique-key", description = "whether to require unique public keys")
    @Completion(Completers.YesNoCompleter.class)
    private String uniqueKeyS;

    @Option(name = "--validity-mode", description = "mode of valditity")
    @Completion(CaCompleters.ValidityModeCompleter.class)
    private String validityModeS;

    @Option(name = "--extra-control", description = "extra control")
    private String extraControl;

    protected ChangeCaEntry getChangeCaEntry() throws Exception {
      ChangeCaEntry entry = new ChangeCaEntry(new NameId(null, caName));

      if (snLen != null) {
        Args.range(snLen, "sn-len", CaManager.MIN_SERIALNUMBER_SIZE, CaManager.MAX_SERIALNUMBER_SIZE);
        entry.setSerialNoLen(snLen);
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

      if (CollectionUtil.isNotEmpty(issuerCertFiles)) {
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
          CaEntry caEntry = caManager.getCa(caName);
          if (caEntry == null) {
            throw new IllegalCmdParamException("please specify the signerType");
          }
          tmpSignerType = caEntry.getSignerType();
        }

        signerConf = ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf, securityFactory);
        entry.setSignerConf(signerConf);
      }

      if (saveCertS != null) {
        entry.setSaveCert(isEnabled(saveCertS, true, "save-cert"));
      }

      if (saveKeypairS != null) {
        entry.setSaveKeypair(isEnabled(saveKeypairS, false, "save-keypair"));
      }

      if (uniqueKeyS != null) {
        entry.setUniqueKey(isEnabled(uniqueKeyS, false, "unique-key"));
      }

      if (CollectionUtil.isNotEmpty(permissions)) {
        entry.setPermission(ShellUtil.getPermission(permissions));
      }

      entry.setCaUris(new CaUris(getUris(caCertUris), getUris(ocspUris), getUris(crlUris), getUris(deltaCrlUris)));

      if (validityModeS != null) {
        entry.setValidityMode(ValidityMode.forName(validityModeS));
      }

      if (maxValidity != null) {
        entry.setMaxValidity(Validity.getInstance(maxValidity));
      }

      if (crlControl != null) {
        entry.setCrlControl(crlControl);
      }

      if (ctlogControl != null) {
        entry.setCtlogControl(ctlogControl);
      }

      if (revokeSuspendedControl != null) {
        entry.setRevokeSuspendedControl(revokeSuspendedControl);
      }

      if (crlSignerName != null) {
        entry.setCrlSignerName(crlSignerName);
      }

      if (CollectionUtil.isNotEmpty(keypairGenNames)) {
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
    } // method getChangeCaEntry

    @Override
    protected Object execute0() throws Exception {
      try {
        caManager.changeCa(getChangeCaEntry());
        println("updated CA " + caName);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not update CA " + caName + ", error: " + ex.getMessage(), ex);
      }
    } // method execute0

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
    } // method getUris

  } // class CaUp

}
