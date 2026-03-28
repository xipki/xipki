// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CaMgmtException;
import org.xipki.ca.api.mgmt.CaProfileEntry;
import org.xipki.ca.api.mgmt.CaStatus;
import org.xipki.ca.api.mgmt.CrlControl;
import org.xipki.ca.api.mgmt.CtlogControl;
import org.xipki.ca.api.mgmt.Permissions;
import org.xipki.ca.api.mgmt.RevokeSuspendedControl;
import org.xipki.ca.api.mgmt.entry.BaseCaInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.security.pkix.CertRevocationInfo;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.extra.type.Validity;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Commands to manage CA.
 *
 * @author Lijun Liao (xipki)
 */
public class CaCommands {

  @Command(name = "ca-add", description = "add CA", mixinStandardHelpOptions = true)
  public static class CaAddCommand extends CaAddOrGenCommand {

    @Option(names = "--cert", description = "CA certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--certchain", description = "certificate chain of CA certificate")
    @Completion(FilePathCompleter.class)
    private List<String> issuerCertFiles;

    @Override
    public void run() {
      try {
        CaEntry caEntry = getCaEntry();
        if (certFile != null) {
          caEntry.setCert(X509Util.parseCert(new File(certFile)));
        }
        if (CollectionUtil.isNotEmpty(issuerCertFiles)) {
          List<X509Cert> chain = new ArrayList<>(issuerCertFiles.size());
          for (String file : issuerCertFiles) {
            chain.add(X509Util.parseCert(new File(file)));
          }
          caEntry.setCertchain(chain);
        }
        client().addCa(caEntry);
        println("added CA " + caEntry.ident().name());
      } catch (Exception ex) {
        throw new RuntimeException("could not add CA " + caName + ": " + ex.getMessage(), ex);
      }
    }
  }

  abstract static class CaAddOrGenCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = {"--name", "-n"}, required = true, description = "CA name")
    protected String caName;

    @Option(names = "--status", description = "CA status")
    @Completion(Completers.StatusCompleter.class)
    protected String caStatus = "active";

    @Option(names = "--ca-cert-uri", description = "CA certificate URI")
    protected List<String> caCertUris;

    @Option(names = "--ocsp-uri", description = "OCSP URI")
    protected List<String> ocspUris;

    @Option(names = "--crl-uri", description = "CRL distribution point")
    protected List<String> crlUris;

    @Option(names = "--deltacrl-uri", description = "Delta CRL distribution point")
    protected List<String> deltaCrlUris;

    @Option(names = "--permission", required = true, description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    protected Set<String> permissions;

    @Option(names = "--sn-len", description = "number of bytes of the serial number")
    protected int snLen = CaManager.MAX_SERIALNUMBER_SIZE;

    @Option(names = "--next-crl-no", required = true, description = "CRL number for the next CRL")
    protected Long nextCrlNumber;

    @Option(names = "--max-validity", required = true, description = "maximal validity")
    protected String maxValidity;

    @Option(names = "--keep-expired-certs", description = "days to keep expired certificates")
    protected Integer keepExpiredCertDays = -1;

    @Option(names = "--crl-signer", description = "CRL signer name")
    @Completion(CaCompleters.SignerNameCompleter.class)
    protected String crlSignerName;

    @Option(names = "--keypair-gen", description = "(ordered) keypair generation names")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    protected List<String> keypairGenNames;

    @Option(names = "--crl-control", description = "CRL control")
    protected String crlControl;

    @Option(names = "--ctlog-control", description = "CT log control")
    protected String ctlogControl;

    @Option(names = "--revoke-suspended-control",
        description = "Revoke suspended certificates control")
    protected String revokeSuspendedControl;

    @Option(names = "--num-crls", description = "number of CRLs to keep in database")
    protected Integer numCrls = 30;

    @Option(names = "--expiration-period", description = "days before expiration time of CA")
    protected Integer expirationPeriod = 365;

    @Option(names = "--signer-type", required = true, description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    protected String signerType;

    @Option(names = "--signer-conf", required = true, description = "CA signer configuration")
    protected String signerConf;

    @Option(names = "--save-cert", description = "whether to save the certificate")
    @Completion(Completers.YesNoCompleter.class)
    protected String saveCertS = "yes";

    @Option(names = "--save-keypair", description = "whether to save the generated keypair")
    @Completion(Completers.YesNoCompleter.class)
    protected String saveKeypairS = "no";

    @Option(names = "--validity-mode", description = "validity mode")
    protected String validityModeS = "STRICT";

    @Option(names = "--extra-control", description = "extra control")
    protected String extraControl;

    protected CaEntry getCaEntry() throws Exception {
      if (snLen < CaManager.MIN_SERIALNUMBER_SIZE || snLen > CaManager.MAX_SERIALNUMBER_SIZE) {
        throw new IllegalArgumentException("invalid sn-len " + snLen);
      }
      if (nextCrlNumber == null || nextCrlNumber < 1) {
        throw new IllegalArgumentException("invalid CRL number: " + nextCrlNumber);
      }
      if (numCrls == null || numCrls < 0) {
        throw new IllegalArgumentException("invalid numCrls: " + numCrls);
      }
      if (expirationPeriod == null || expirationPeriod < 0) {
        throw new IllegalArgumentException("invalid expirationPeriod: " + expirationPeriod);
      }

      String effectiveSignerConf = signerConf;
      if (StringUtil.orEqualsIgnoreCase(signerType, "PKCS12", "JCEKS")) {
        effectiveSignerConf = CaMgmtUtil.canonicalizeSignerConf(signerType, effectiveSignerConf);
      }

      BaseCaInfo base = new BaseCaInfo(signerType, new Permissions(permissions));
      CaEntry entry = new CaEntry(base, new NameId(null, caName), effectiveSignerConf);
      base.setSnSize(snLen);
      base.setNextCrlNo(nextCrlNumber);
      base.setCaUris(new CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris));
      base.setNumCrls(numCrls);
      base.setExpirationPeriod(expirationPeriod);
      base.setKeepExpiredCertDays(keepExpiredCertDays);
      base.setSaveCert(CaMgmtUtil.parseEnabled(saveCertS, true, "save-cert"));
      base.setSaveKeypair(CaMgmtUtil.parseEnabled(saveKeypairS, false, "save-keypair"));
      base.setValidityMode(ValidityMode.forName(validityModeS));
      base.setStatus(CaStatus.forName(caStatus));

      if (crlControl != null) {
        base.setCrlControl(new CrlControl(crlControl));
      }
      if (ctlogControl != null) {
        base.setCtlogControl(new CtlogControl(ctlogControl));
      }
      if (revokeSuspendedControl != null) {
        base.setRevokeSuspendedControl(
            new RevokeSuspendedControl(new ConfPairs(revokeSuspendedControl)));
      }
      if (crlSignerName != null) {
        base.setCrlSignerName(crlSignerName);
      }
      if (CollectionUtil.isNotEmpty(keypairGenNames)) {
        base.setKeypairGenNames(keypairGenNames);
      }
      base.setMaxValidity(Validity.getInstance(maxValidity));

      String trimmedExtra = extraControl == null ? null : extraControl.trim();
      if (StringUtil.isNotBlank(trimmedExtra)) {
        base.setExtraControl(new ConfPairs(trimmedExtra).unmodifiable());
      }
      return entry;
    }
  }

  @Command(name = "caalias-add", description = "add CA alias", mixinStandardHelpOptions = true)
  public static class CaaliasAddCommand extends CaMgmtUtil.CaMgmtCommand {

    @Option(names = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--alias", required = true, description = "CA alias")
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String caAlias;

    @Override
    public void run() {
      try {
        client().addCaAlias(caAlias, caName);
        println("added CA alias " + caAlias + " associated with CA " + caName);
      } catch (Exception ex) {
        throw new RuntimeException("could not add CA alias: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "caalias-info", description = "show information of CA alias",
      mixinStandardHelpOptions = true)
  static class CaaliasInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "CA alias")
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String caAlias;

    @Override
    public void run() {
      try {
        Set<String> aliasNames = client().getCaAliasNames();
        if (caAlias == null) {
          println(CaMgmtUtil.formatNames("CA alias", aliasNames));
          return;
        }

        if (!aliasNames.contains(caAlias)) {
          throw new CaMgmtException("could not find CA alias '" + caAlias + "'");
        }

        println(caAlias + "\n\t" + client().getCaNameForAlias(caAlias));
      } catch (Exception ex) {
        throw new RuntimeException("could not get CA alias info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "caalias-rm", description = "remove CA alias", mixinStandardHelpOptions = true)
  public static class CaaliasRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA alias")
    @Completion(CaCompleters.CaAliasCompleter.class)
    private String caAlias;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove CA alias " + caAlias)) {
          client().removeCaAlias(caAlias);
          println("removed CA alias " + caAlias);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove CA alias " + caAlias + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "gen-rootca", description = "generate root CA certificate",
      mixinStandardHelpOptions = true)
  public static class GenRootcaCommand extends CaAddOrGenCommand {

    @Option(names = "--subject", required = true, description = "subject")
    private String subject;

    @Option(names = "--profile", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String profileName;

    @Option(names = "--serial", description = "serial number")
    private String serialNumber;

    @Option(names = "--not-before", description = "notBefore UTC yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(names = "--not-after", description = "notAfter UTC yyyyMMddHHmmss")
    private String notAfterS;

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "certificate output file")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        CaEntry caEntry = getCaEntry();
        X509Cert cert = client().generateRootCa(caEntry, profileName, subject, serialNumber,
                          CaMgmtUtil.parseDate(notBeforeS), CaMgmtUtil.parseDate(notAfterS));
        saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(),
            outform));
      } catch (Exception ex) {
        throw new RuntimeException("could not generate root CA " + caName + ": "
            + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cacert", description = "get CA's certificate", mixinStandardHelpOptions = true)
  static class CaCertCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(names = "--outform", description = "output format der|pem")
    @Completion(Completers.OutformCompleter.class)
    private String outform = "der";

    @Option(names = {"--out", "-o"}, required = true, description = "output file")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        List<X509Cert> certs = client().getCaCerts(name);
        if ("der".equalsIgnoreCase(outform)) {
          IoUtil.save(outFile, certs.get(0).getEncoded());
        } else if ("pem".equalsIgnoreCase(outform)) {
          IoUtil.save(outFile, X509Util.toPemCert(certs.get(0)).getBytes());
        } else {
          throw new IllegalArgumentException("invalid outform " + outform);
        }
        println("saved CA certificate to " + outFile);
      } catch (Exception ex) {
        throw new RuntimeException("could not export CA certificate: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "cacerts", description = "get CA's certificate chain",
      mixinStandardHelpOptions = true)
  static class CaCertsCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(names = {"--out", "-o"}, required = true, description = "output PEM file")
    @Completion(FilePathCompleter.class)
    private String outFile;

    @Override
    public void run() {
      try {
        List<X509Cert> certs = client().getCaCerts(name);
        IoUtil.save(outFile,
            X509Util.encodeCertificates(certs.toArray(new X509Cert[0])).getBytes());
        println("saved CA certificate chain to " + outFile);
      } catch (Exception ex) {
        throw new RuntimeException("could not export CA certificate chain: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-info", description = "show information of CA",
      mixinStandardHelpOptions = true)
  static class CaInfoCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", arity = "0..1", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(names = {"--verbose", "-v"}, description = "show CA information verbosely")
    private boolean verbose;

    @Override
    public void run() {
      try {
        CaMgmtClient client = client();
        if (name == null) {
          StringBuilder sb = new StringBuilder();
          CaMgmtUtil.appendLabeledCaNames(sb, "successful CAs",
              client.getSuccessfulCaNames(), client);
          CaMgmtUtil.appendLabeledCaNames(sb, "failed CAs", client.getFailedCaNames(), client);
          CaMgmtUtil.appendLabeledCaNames(sb, "inactive CAs",
              client.getInactiveCaNames(), client);
          println(sb.toString());
          return;
        }

        CaEntry caEntry = Optional.ofNullable(client.getCa(name))
            .orElseThrow(() -> new CaMgmtException("could not find CA '" + name + "'"));
        StringBuilder sb = new StringBuilder();
        if (caEntry.base().status() != null
            && "active".equalsIgnoreCase(caEntry.base().status().name())) {
          boolean started = client.getSuccessfulCaNames().contains(caEntry.ident().name());
          sb.append("started:              ").append(started).append('\n');
        }
        Set<String> aliases = client.getAliasesForCa(name);
        sb.append("aliases:              ")
            .append(CollectionUtil.isEmpty(aliases) ? "-" : aliases.toString()).append('\n');
        sb.append(caEntry.toString(verbose));

        Set<String> publisherNames = client.getPublisherNamesForCa(name);
        sb.append("\nAssociated publishers:");
        if (CollectionUtil.isEmpty(publisherNames)) {
          sb.append(" -");
        } else {
          List<String> names = new ArrayList<>(publisherNames);
          Collections.sort(names);
          sb.append(' ').append(names);
        }

        Set<CaProfileEntry> profiles = client.getCertprofilesForCa(name);
        sb.append("\nAssociated certificate profiles:");
        if (CollectionUtil.isEmpty(profiles)) {
          sb.append(" -");
        } else {
          sb.append(' ').append(profiles).append(' ');
        }

        Set<CaHasRequestorEntry> requestors = client.getRequestorsForCa(name);
        sb.append("\nAssociated requestors:");
        if (CollectionUtil.isEmpty(requestors)) {
          sb.append(" -");
        } else {
          for (CaHasRequestorEntry m : requestors) {
            sb.append("\n\t").append(m.requestorIdent().name())
                .append(", permissions=").append(m.permissions())
                .append(", profiles=").append(m.profiles());
          }
        }
        println(sb.toString());
      } catch (Exception ex) {
        throw new RuntimeException("could not get CA info: " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-rm", description = "remove CA", mixinStandardHelpOptions = true)
  public static class CaRmCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String name;

    @Option(names = {"--force", "-f"}, description = "without prompt")
    private boolean force;

    @Override
    public void run() {
      try {
        if (force || confirmAction("Do you want to remove CA " + name)) {
          client().removeCa(name);
          println("removed CA " + name);
        }
      } catch (Exception ex) {
        throw new RuntimeException("could not remove CA " + name + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-revoke", description = "revoke CA", mixinStandardHelpOptions = true)
  public static class CaRevokeCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--reason", required = true, description = "CRL reason")
    @Completion(Completers.CrlReasonCompleter.class)
    private String reason;

    @Option(names = "--rev-date", description = "revocation date UTC yyyyMMddHHmmss")
    private String revocationDateS;

    @Option(names = "--inv-date", description = "invalidity date UTC yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    public void run() {
      try {
        CrlReason crlReason = CrlReason.forNameOrText(reason);
        Instant revocationDate = StringUtil.isBlank(revocationDateS)
            ? Instant.now() : DateUtil.parseUtcTimeyyyyMMddhhmmss(revocationDateS);
        Instant invalidityDate = StringUtil.isBlank(invalidityDateS)
            ? null : DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
        client().revokeCa(caName,
            new CertRevocationInfo(crlReason, revocationDate, invalidityDate));
        println("revoked CA " + caName);
      } catch (Exception ex) {
        throw new RuntimeException("could not revoke CA " + caName + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-unrevoke", description = "unrevoke CA", mixinStandardHelpOptions = true)
  public static class CaUnrevokeCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Override
    public void run() {
      try {
        client().unrevokeCa(caName);
        println("unrevoked CA " + caName);
      } catch (Exception ex) {
        throw new RuntimeException("could not unrevoke CA " + caName + ": " + ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "ca-up", description = "update CA", mixinStandardHelpOptions = true)
  public static class CaUpCommand extends CaMgmtUtil.CaMgmtCommand {

    @Parameters(index = "0", description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(names = "--sn-len", description = "number of octets of the serial number")
    private Integer snLen;

    @Option(names = "--status", description = "CA status")
    @Completion(Completers.StatusCompleter.class)
    private String caStatus;

    @Option(names = "--ca-cert-uri", description = "CA certificate URI")
    private List<String> caCertUris;

    @Option(names = "--ocsp-uri", description = "OCSP URI or 'null'")
    private List<String> ocspUris;

    @Option(names = "--crl-uri", description = "CRL distribution point URI or 'null'")
    private List<String> crlUris;

    @Option(names = "--deltacrl-uri", description = "Delta CRL URI or 'null'")
    private List<String> deltaCrlUris;

    @Option(names = "--permission", description = "permission")
    @Completion(CaCompleters.PermissionCompleter.class)
    private List<String> permissions;

    @Option(names = "--max-validity", description = "maximal validity")
    private String maxValidity;

    @Option(names = "--expiration-period", description = "days before expiration time of CA")
    private Integer expirationPeriod;

    @Option(names = "--keep-expired-certs", description = "days to keep expired certificates")
    private Integer keepExpiredCertDays;

    @Option(names = "--crl-signer", description = "CRL signer name or 'null'")
    @Completion(CaCompleters.SignerNamePlusNullCompleter.class)
    private String crlSignerName;

    @Option(names = "--keypair-gen", description = "(ordered) keypair generation names or 'null'")
    @Completion(CaCompleters.KeypairGenNameCompleter.class)
    private List<String> keypairGenNames;

    @Option(names = "--crl-control", description = "CRL control or 'null'")
    private String crlControl;

    @Option(names = "--ctlog-control", description = "CT log control")
    private String ctlogControl;

    @Option(names = "--revoke-suspended-control",
        description = "Revoke suspended certificates control")
    private String revokeSuspendedControl;

    @Option(names = "--num-crls", description = "number of CRLs to be kept in database")
    private Integer numCrls;

    @Option(names = "--cert", description = "CA certificate file")
    @Completion(FilePathCompleter.class)
    private String certFile;

    @Option(names = "--certchain", description = "certificate chain of CA certificate")
    @Completion(FilePathCompleter.class)
    private List<String> issuerCertFiles;

    @Option(names = "--signer-type", description = "CA signer type")
    @Completion(CaCompleters.SignerTypeCompleter.class)
    private String signerType;

    @Option(names = "--signer-conf", description = "CA signer configuration or 'null'")
    private String signerConf;

    @Option(names = "--save-cert", description = "whether to save the certificate")
    @Completion(Completers.YesNoCompleter.class)
    private String saveCertS;

    @Option(names = "--save-keypair", description = "whether to save the generated keypair")
    @Completion(Completers.YesNoCompleter.class)
    private String saveKeypairS;

    @Option(names = "--validity-mode", description = "validity mode")
    @Completion(CaCompleters.ValidityModeCompleter.class)
    private String validityModeS;

    @Option(names = "--extra-control", description = "extra control")
    private String extraControl;

    @Override
    public void run() {
      try {
        client().changeCa(getChangeCaEntry());
        println("updated CA " + caName);
      } catch (Exception ex) {
        throw new RuntimeException("could not update CA " + caName + ": " + ex.getMessage(), ex);
      }
    }

    private ChangeCaEntry getChangeCaEntry() throws Exception {
      ChangeCaEntry entry = new ChangeCaEntry(new NameId(null, caName));
      if (snLen != null) {
        if (snLen < CaManager.MIN_SERIALNUMBER_SIZE || snLen > CaManager.MAX_SERIALNUMBER_SIZE) {
          throw new IllegalArgumentException("invalid sn-len " + snLen);
        }
        entry.setSerialNoLen(snLen);
      }
      if (caStatus != null) {
        entry.setStatus(CaStatus.forName(caStatus));
      }
      if (expirationPeriod != null && expirationPeriod < 0) {
        throw new IllegalArgumentException("invalid expirationPeriod: " + expirationPeriod);
      } else {
        entry.setExpirationPeriod(expirationPeriod);
      }
      if (keepExpiredCertDays != null) {
        entry.setKeepExpiredCertDays(keepExpiredCertDays);
      }
      if (certFile != null) {
        entry.setEncodedCert(IoUtil.read(certFile));
      }
      if (CollectionUtil.isNotEmpty(issuerCertFiles)) {
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
        String effectiveType = signerType;
        if (effectiveType == null) {
          CaEntry caEntry = Optional.ofNullable(client().getCa(caName))
              .orElseThrow(() -> new IllegalArgumentException("please specify the signerType"));
          effectiveType = caEntry.base().signerType();
        }
        entry.setSignerConf(CaMgmtUtil.canonicalizeSignerConf(effectiveType, signerConf));
      }
      if (saveCertS != null) {
        entry.setSaveCert(CaMgmtUtil.parseEnabled(saveCertS, true, "save-cert"));
      }
      if (saveKeypairS != null) {
        entry.setSaveKeypair(CaMgmtUtil.parseEnabled(saveKeypairS, false, "save-keypair"));
      }
      if (CollectionUtil.isNotEmpty(permissions)) {
        entry.setPermissions(permissions);
      }
      entry.setCaUris(new CaUris(CaMgmtUtil.getUris(caCertUris), CaMgmtUtil.getUris(ocspUris),
          CaMgmtUtil.getUris(crlUris), CaMgmtUtil.getUris(deltaCrlUris)));
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
    }
  }
}
