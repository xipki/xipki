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

package org.xipki.ca.server.mgmt;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.ca.api.CertificateInfo;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.RequestType;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaEntry.CaSignerConf;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.server.*;
import org.xipki.ca.server.cmp.CmpResponder;
import org.xipki.ca.server.db.CaManagerQueryExecutor;
import org.xipki.ca.server.mgmt.SelfSignedCertBuilder.GenerateSelfSignedResult;
import org.xipki.datasource.DataAccessException;
import org.xipki.security.*;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;
import org.xipki.util.http.SslContextConf;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.*;

import static org.xipki.ca.server.CaAuditConstants.*;
import static org.xipki.ca.server.CaUtil.canonicalizeSignerConf;
import static org.xipki.util.Args.*;
import static org.xipki.util.StringUtil.concat;

/**
 * Manages the CAs.
 *
 * @author Lijun Liao
 */

class Ca2Manager {

  private static final Logger LOG = LoggerFactory.getLogger(Ca2Manager.class);

  private boolean caAliasesInitialized;

  private boolean casInitialized;

  private final CaManagerImpl manager;

  Ca2Manager(CaManagerImpl manager) {
    this.manager = notNull(manager, "manager");
  } // constructor

  void reset() {
    caAliasesInitialized = false;
    casInitialized = false;
  }

  void close() {
    for (String caName : manager.x509cas.keySet()) {
      X509Ca ca = manager.x509cas.get(caName);
      try {
        ca.close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, concat("could not call ca.close() for CA ", caName));
      }
    }
  }

  void restartCa(String name) throws CaMgmtException {
    assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");

    NameId ident = manager.idNameMap.getCa(name);
    if (ident == null) {
      throw new CaMgmtException("Unknown CA " + name);
    }

    if (createCa(name)) {
      CaInfo caInfo = manager.caInfos.get(name);
      if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
        return;
      }

      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method restartCa

  boolean startCa(String caName) {
    CaInfo caEntry = manager.caInfos.get(caName);

    CtlogControl ctlogControl = caEntry.getCaEntry().getCtlogControl();
    CtLogClient ctlogClient = null;
    if (ctlogControl != null && ctlogControl.isEnabled()) {
      String name = ctlogControl.getSslContextName();
      SslContextConf ctxConf;
      if (name == null) {
        ctxConf = null;
      } else {
        ctxConf = manager.caServerConf.getSslContextConf(name);
        if (ctxConf == null) {
          LOG.error(concat("getSslContextConf (ca=", caName,
              "): found no SslContext named " + name));
          return false;
        } else {
          try {
            ctxConf.getSslContext();
          } catch (ObjectCreationException ex) {
            LOG.error(concat("startCa (ca=", caName,
                        "): could not initialize SslContext named " + name));
            return false;
          }
        }
      }
      ctlogClient = new CtLogClient(ctlogControl.getServers(), ctxConf);
    }

    X509Ca ca;
    try {
      ca = new X509Ca(manager, caEntry, manager.certstore, ctlogClient);
    } catch (OperationException ex) {
      LogUtil.error(LOG, ex, concat("X509CA.<init> (ca=", caName, ")"));
      return false;
    }

    manager.x509cas.put(caName, ca);
    CmpResponder caResponder;
    try {
      caResponder = new CmpResponder(manager, caName);
    } catch (NoSuchAlgorithmException ex) {
      LogUtil.error(LOG, ex, concat("CmpResponder.<init> (ca=", caName, ")"));
      return false;
    }

    manager.cmpResponders.put(caName, caResponder);

    if (caEntry.getScepResponderName() != null) {
      try {
        manager.scepResponders.put(caName, new ScepResponder(manager, caEntry.getCaEntry()));
      } catch (CaMgmtException ex) {
        LogUtil.error(LOG, ex, concat("ScepResponder.<init> (ca=", caName, ")"));
        return false;
      }
    }
    return true;
  } // method startCa

  Set<String> getCaNames() {
    return manager.caInfos.keySet();
  }

  Set<String> getSuccessfulCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : manager.x509cas.keySet()) {
      if (CaStatus.ACTIVE == manager.caInfos.get(name).getStatus()) {
        ret.add(name);
      }
    }
    return ret;
  } // method getSuccessfulCaNames

  Set<String> getFailedCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : manager.caInfos.keySet()) {
      if (CaStatus.ACTIVE == manager.caInfos.get(name).getStatus()
          && !manager.x509cas.containsKey(name)) {
        ret.add(name);
      }
    }
    return ret;
  } // method getFailedCaNames

  Set<String> getInactiveCaNames() {
    Set<String> ret = new HashSet<>();
    for (String name : manager.caInfos.keySet()) {
      if (CaStatus.INACTIVE == manager.caInfos.get(name).getStatus()) {
        ret.add(name);
      }
    }
    return ret;
  } // method getInactiveCaNames

  void initCaAliases() throws CaMgmtException {
    if (caAliasesInitialized) {
      return;
    }

    Map<String, Integer> map = manager.queryExecutor.createCaAliases();
    manager.caAliases.clear();
    for (String aliasName : map.keySet()) {
      manager.caAliases.put(aliasName, map.get(aliasName));
    }

    LOG.info("caAliases: {}", manager.caAliases);
    caAliasesInitialized = true;
  } // method initCaAliases

  void initCas() throws CaMgmtException {
    if (casInitialized) {
      return;
    }

    manager.caInfos.clear();
    manager.caHasRequestors.clear();
    manager.caHasPublishers.clear();
    manager.caHasProfiles.clear();
    manager.idNameMap.clearCa();

    List<String> names = manager.queryExecutor.namesFromTable("CA");
    for (String name : names) {
      createCa(name);
    }
    casInitialized = true;
  } // method initCas

  boolean createCa(String name) throws CaMgmtException {
    manager.caInfos.remove(name);
    manager.idNameMap.removeCa(name);
    manager.caHasProfiles.remove(name);
    manager.caHasPublishers.remove(name);
    manager.caHasRequestors.remove(name);
    X509Ca oldCa = manager.x509cas.remove(name);
    manager.cmpResponders.remove(name);
    manager.scepResponders.remove(name);
    if (oldCa != null) {
      oldCa.close();
    }

    CaManagerQueryExecutor queryExecutor = manager.queryExecutor;

    CaInfo ca = queryExecutor.createCaInfo(name, manager.certstore);
    LOG.info("created CA {}: {}", name, ca.toString(false));
    manager.caInfos.put(name, ca);
    manager.idNameMap.addCa(ca.getIdent());
    Set<CaHasRequestorEntry> caReqEntries = queryExecutor.createCaHasRequestors(ca.getIdent());
    manager.caHasRequestors.put(name, caReqEntries);
    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder();
      for (CaHasRequestorEntry entry : caReqEntries) {
        sb.append("\n    ").append(entry);
      }
      LOG.info("CA {} is associated requestors:{}", name, sb);
    }

    Set<Integer> profileIds = queryExecutor.createCaHasProfiles(ca.getIdent());
    Set<String> profileNames = new HashSet<>();
    for (Integer id : profileIds) {
      profileNames.add(manager.idNameMap.getCertprofileName(id));
    }
    manager.caHasProfiles.put(name, profileNames);
    LOG.info("CA {} is associated with profiles: {}", name, profileNames);

    Set<Integer> publisherIds = queryExecutor.createCaHasPublishers(ca.getIdent());
    Set<String> publisherNames = new HashSet<>();
    for (Integer id : publisherIds) {
      publisherNames.add(manager.idNameMap.getPublisherName(id));
    }
    manager.caHasPublishers.put(name, publisherNames);
    LOG.info("CA {} is associated with publishers: {}", name, publisherNames);

    return true;
  } // method createCa

  void addCa(CaEntry caEntry) throws CaMgmtException {
    assertMasterModeAndSetuped();

    notNull(caEntry, "caEntry");

    NameId ident = caEntry.getIdent();
    String name = ident.getName();

    if (manager.caInfos.containsKey(name)) {
      throw new CaMgmtException(concat("CA named ", name, " exists"));
    }

    SecurityFactory securityFactory = manager.securityFactory;
    String origSignerConf = caEntry.getSignerConf();
    String newSignerConf = canonicalizeSignerConf(caEntry.getSignerType(),
        origSignerConf, null, securityFactory);
    if (!origSignerConf.equals(newSignerConf)) {
      caEntry.setSignerConf(newSignerConf);
    }

    try {
      List<CaSignerConf> signerConfs = CaEntry.splitCaSignerConfs(caEntry.getSignerConf());
      ConcurrentContentSigner signer;
      for (CaSignerConf m : signerConfs) {
        SignerConf signerConf = new SignerConf(m.getConf());
        signer = securityFactory.createSigner(caEntry.getSignerType(), signerConf,
            caEntry.getCert());
        if (caEntry.getCert() == null) {
          if (signer.getCertificate() == null) {
            throw new CaMgmtException("CA signer without certificate is not allowed");
          }
          caEntry.setCert(signer.getCertificate());
        }
      }
    } catch (XiSecurityException | ObjectCreationException ex) {
      throw new CaMgmtException(
        concat("could not create signer for new CA ", name, ": ", ex.getMessage()), ex);
    }

    manager.queryExecutor.addCa(caEntry);
    if (createCa(name)) {
      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method addCa

  CaEntry getCa(String name) {
    CaInfo caInfo = manager.caInfos.get(toNonBlankLower(name, "name"));
    return (caInfo == null) ? null : caInfo.getCaEntry();
  } // method getCa

  void changeCa(ChangeCaEntry entry) throws CaMgmtException {
    assertMasterModeAndSetuped();

    notNull(entry, "entry");

    String name = entry.getIdent().getName();
    NameId ident = manager.idNameMap.getCa(name);
    if (ident == null) {
      throw new CaMgmtException("Unknown CA " + name);
    }

    entry.getIdent().setId(ident.getId());

    manager.queryExecutor.changeCa(entry, manager.caInfos.get(name).getCaEntry(),
        manager.securityFactory);

    if (createCa(name)) {
      CaInfo caInfo = manager.caInfos.get(name);
      if (CaStatus.ACTIVE != caInfo.getCaEntry().getStatus()) {
        return;
      }

      if (startCa(name)) {
        LOG.info("started CA {}", name);
      } else {
        LOG.error("could not start CA {}", name);
      }
    } else {
      LOG.error("could not create CA {}", name);
    }
  } // method changeCa

  void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    assertMasterModeAndSetuped();

    aliasName = toNonBlankLower(aliasName, "aliasName");
    caName = toNonBlankLower(caName, "caName");

    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + caName);
    }

    if (manager.caAliases.get(aliasName) != null) {
      throw new CaMgmtException("unknown CA alias " + aliasName);
    }

    manager.queryExecutor.addCaAlias(aliasName, ca.getCaIdent());
    manager.caAliases.put(aliasName, ca.getCaIdent().getId());
  } // method addCaAlias

  void removeCaAlias(String name) throws CaMgmtException {
    assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");
    manager.queryExecutor.removeCaAlias(name);
    manager.caAliases.remove(name);
  } // method removeCaAlias

  String getCaNameForAlias(String aliasName) {
    aliasName = toNonBlankLower(aliasName, "aliasName");
    Integer caId = manager.caAliases.get(aliasName);
    for (String name : manager.x509cas.keySet()) {
      X509Ca ca = manager.x509cas.get(name);
      if (ca.getCaIdent().getId().equals(caId)) {
        return ca.getCaIdent().getName();
      }
    }
    return null;
  } // method getCaNameForAlias

  Set<String> getAliasesForCa(String caName) {
    caName = toNonBlankLower(caName, "caName");
    Set<String> aliases = new HashSet<>();
    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      return aliases;
    }

    NameId caIdent = ca.getCaIdent();

    for (String alias : manager.caAliases.keySet()) {
      Integer thisCaId = manager.caAliases.get(alias);
      if (caIdent.getId().equals(thisCaId)) {
        aliases.add(alias);
      }
    }

    return aliases;
  } // method getAliasesForCa

  X509Cert getCaCert(String caName) {
    caName = toNonBlankLower(caName, "caName");
    X509Ca ca = manager.x509cas.get(caName);
    return (ca == null) ? null : ca.getCaInfo().getCert();
  } // method getCaCert

  List<X509Cert> getCaCertchain(String caName) {
    caName = toNonBlankLower(caName, "caName");
    X509Ca ca = manager.x509cas.get(caName);
    return (ca == null) ? null : ca.getCaInfo().getCertchain();
  } // method getCaCertchain

  void removeCa(String name) throws CaMgmtException {
    assertMasterModeAndSetuped();

    name = toNonBlankLower(name, "name");

    manager.queryExecutor.removeCa(name);

    LOG.info("removed CA '{}'", name);
    manager.caInfos.remove(name);
    manager.idNameMap.removeCa(name);
    manager.idNameMap.removeCa(name);
    manager.caHasProfiles.remove(name);
    manager.caHasPublishers.remove(name);
    manager.caHasRequestors.remove(name);
    X509Ca ca = manager.x509cas.remove(name);
    manager.cmpResponders.remove(name);
    manager.scepResponders.remove(name);
    if (ca != null) {
      ca.close();
    }
  } // method removeCa

  void revokeCa(String caName, CertRevocationInfo revocationInfo) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");
    notNull(revocationInfo, "revocationInfo");

    if (!manager.x509cas.containsKey(caName)) {
      throw new CaMgmtException(concat("unkown CA ", caName));
    }

    LOG.info("revoking CA '{}'", caName);
    X509Ca ca = manager.x509cas.get(caName);

    CertRevocationInfo currentRevInfo = ca.getCaInfo().getRevocationInfo();
    if (currentRevInfo != null) {
      CrlReason currentReason = currentRevInfo.getReason();
      if (currentReason != CrlReason.CERTIFICATE_HOLD) {
        throw new CaMgmtException(concat("CA ", caName, " has been revoked with reason ",
            currentReason.name()));
      }
    }

    manager.queryExecutor.revokeCa(caName, revocationInfo);

    try {
      ca.revokeCa(revocationInfo, MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(concat("could not revoke CA ", ex.getMessage()), ex);
    }
    LOG.info("revoked CA '{}'", caName);
    CaManagerImpl.auditLogPciEvent(true, concat("REVOKE CA ", caName));
  } // method revokeCa

  void unrevokeCa(String caName) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");

    if (!manager.x509cas.containsKey(caName)) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    LOG.info("unrevoking of CA '{}'", caName);

    manager.queryExecutor.unrevokeCa(caName);

    X509Ca ca = manager.x509cas.get(caName);
    try {
      ca.unrevokeCa(MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(
          concat("could not unrevoke CA " + caName + ": ", ex.getMessage()), ex);
    }
    LOG.info("unrevoked CA '{}'", caName);

    CaManagerImpl.auditLogPciEvent(true, concat("UNREVOKE CA ", caName));
  } // method unrevokeCa

  X509Ca getX509Ca(String name) throws CaMgmtException {
    name = toNonBlankLower(name, "name");
    X509Ca ca = manager.x509cas.get(name);
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + name);
    }
    return ca;
  } // method getX509Ca

  X509Ca getX509Ca(NameId ident) throws CaMgmtException {
    notNull(ident, "ident");
    X509Ca ca = manager.x509cas.get(ident.getName());
    if (ca == null) {
      throw new CaMgmtException("unknown CA " + ident);
    }
    return ca;
  } // method getX509Ca

  X509Cert generateRootCa(CaEntry caEntry, String profileName, String subject,
      String serialNumber) throws CaMgmtException {
    assertMasterModeAndSetuped();

    notNull(caEntry, "caEntry");
    profileName = toNonBlankLower(profileName, "profileName");
    notBlank(subject, "subject");

    int numCrls = caEntry.getNumCrls();
    String signerType = caEntry.getSignerType();

    if (numCrls < 0) {
      System.err.println("invalid numCrls: " + numCrls);
      return null;
    }

    int expirationPeriod = caEntry.getExpirationPeriod();
    if (expirationPeriod < 0) {
      System.err.println("invalid expirationPeriod: " + expirationPeriod);
      return null;
    }

    IdentifiedCertprofile certprofile = manager.getIdentifiedCertprofile(profileName);
    if (certprofile == null) {
      throw new CaMgmtException(concat("unknown certprofile ", profileName));
    }

    BigInteger serialOfThisCert;
    if (serialNumber == null) {
      serialOfThisCert = BigInteger.ONE;
    } else if (StringUtil.startsWithIgnoreCase(serialNumber, "RANDOM:")) {
      int numBytes = -1;
      try {
        numBytes = Integer.parseUnsignedInt(serialNumber.substring("RANDOM:".length()));
      } catch (NumberFormatException ex) {
        LogUtil.error(LOG, ex, "cannot parse int in " + serialNumber);
      }

      if (numBytes < 1 || numBytes > 20) {
        throw new CaMgmtException(concat("invalid SerialNumber for SelfSigned " + serialNumber,
                profileName));
      }
      byte[] bytes = new byte[numBytes];
      SecureRandom rnd = new SecureRandom();
      rnd.nextBytes(bytes);
      // clear the highest bit
      bytes[0] &= 0x7F;
      serialOfThisCert = new BigInteger(bytes);
    } else {
      if (StringUtil.startsWithIgnoreCase(serialNumber, "0x")) {
        serialOfThisCert = new BigInteger(serialNumber.substring(2), 16);
      } else {
        serialOfThisCert = new BigInteger(serialNumber);
      }
    }

    GenerateSelfSignedResult result;
    try {
      result = SelfSignedCertBuilder.generateSelfSigned(manager.securityFactory, signerType,
          caEntry.getSignerConf(), certprofile, subject, serialOfThisCert, caEntry.getCaUris(),
          caEntry.getExtraControl());
    } catch (OperationException | InvalidConfException ex) {
      throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
    }

    String signerConf = result.getSignerConf();
    X509Cert caCert = result.getCert();

    if ("PKCS12".equalsIgnoreCase(signerType) || "JCEKS".equalsIgnoreCase(signerType)) {
      try {
        signerConf = canonicalizeSignerConf(signerType, signerConf,
            new X509Cert[]{caCert}, manager.securityFactory);
      } catch (Exception ex) {
        throw new CaMgmtException(concat(ex.getClass().getName(), ": ", ex.getMessage()), ex);
      }
    }

    String name = caEntry.getIdent().getName();
    long nextCrlNumber = caEntry.getNextCrlNumber();

    CaEntry entry = new CaEntry(new NameId(null, name), caEntry.getSerialNoLen(),
        nextCrlNumber, signerType, signerConf, caEntry.getCaUris(), numCrls, expirationPeriod);
    entry.setCert(caCert);
    entry.setCmpControl(caEntry.getCmpControl());
    entry.setCrlControl(caEntry.getCrlControl());
    entry.setScepControl(caEntry.getScepControl());
    entry.setCmpResponderName(caEntry.getCmpResponderName());
    entry.setScepResponderName(caEntry.getScepResponderName());
    entry.setCrlSignerName(caEntry.getCrlSignerName());
    entry.setExtraControl(caEntry.getExtraControl());
    entry.setKeepExpiredCertInDays(caEntry.getKeepExpiredCertInDays());
    entry.setMaxValidity(caEntry.getMaxValidity());
    entry.setPermission(caEntry.getPermission());
    entry.setProtocolSupport(caEntry.getProtocoSupport());
    entry.setSaveRequest(caEntry.isSaveRequest());
    entry.setStatus(caEntry.getStatus());
    entry.setValidityMode(caEntry.getValidityMode());

    addCa(entry);
    return caCert;
  } // method generateRootCa

  X509Cert generateCertificate(String caName, String profileName, byte[] encodedCsr,
      Date notBefore, Date notAfter) throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    profileName = toNonBlankLower(profileName, "profileName");
    notNull(encodedCsr, "encodedCsr");

    AuditEvent event = new AuditEvent(new Date());
    event.setApplicationName(APPNAME);
    event.setName(NAME_perf);
    event.addEventType("CAMGMT_CRL_GEN_ONDEMAND");

    X509Ca ca = getX509Ca(caName);
    CertificationRequest csr;
    try {
      csr = X509Util.parseCsr(encodedCsr);
    } catch (Exception ex) {
      throw new CaMgmtException(concat("invalid CSR request. ERROR: ", ex.getMessage()));
    }

    if (!ca.verifyCsr(csr)) {
      throw new CaMgmtException("could not validate POP for the CSR");
    }

    CertificationRequestInfo certTemp = csr.getCertificationRequestInfo();
    Extensions extensions = null;
    ASN1Set attrs = certTemp.getAttributes();
    for (int i = 0; i < attrs.size(); i++) {
      Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
      if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
        extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
      }
    }

    X500Name subject = certTemp.getSubject();
    SubjectPublicKeyInfo publicKeyInfo = certTemp.getSubjectPublicKeyInfo();

    CertTemplateData certTemplateData = new CertTemplateData(subject, publicKeyInfo,
        notBefore, notAfter, extensions, profileName);

    CertificateInfo certInfo;
    try {
      certInfo = ca.generateCert(certTemplateData, manager.byCaRequestor, RequestType.CA,
              null, MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }

    if (ca.getCaInfo().isSaveRequest()) {
      try {
        long dbId = ca.addRequest(encodedCsr);
        ca.addRequestCert(dbId, certInfo.getCert().getCertId());
      } catch (OperationException ex) {
        LogUtil.warn(LOG, ex, "could not save request");
      }
    }

    return certInfo.getCert().getCert();
  } // method generateCertificate

  void revokeCertificate(String caName, BigInteger serialNumber, CrlReason reason,
      Date invalidityTime) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");
    notNull(serialNumber, "serialNumber");

    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.revokeCert(serialNumber, reason, invalidityTime,
          MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not revoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method revokeCertificate

  void unrevokeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");
    notNull(serialNumber, "serialNumber");

    X509Ca ca = getX509Ca(caName);
    try {
      if (ca.unrevokeCert(serialNumber, MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not unrevoke non-existing certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method unrevokeCertificate

  void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");
    notNull(serialNumber, "serialNumber");
    X509Ca ca = getX509Ca(caName);
    if (ca == null) {
      throw manager.logAndCreateException(concat("unknown CA ", caName));
    }

    try {
      if (ca.removeCert(serialNumber, MSGID_ca_mgmt) == null) {
        throw new CaMgmtException("could not remove certificate");
      }
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method removeCertificate

  X509CRLHolder generateCrlOnDemand(String caName) throws CaMgmtException {
    assertMasterModeAndSetuped();

    caName = toNonBlankLower(caName, "caName");

    X509Ca ca = getX509Ca(caName);
    try {
      return ca.generateCrlOnDemand(MSGID_ca_mgmt);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method generateCrlOnDemand

  X509CRLHolder getCrl(String caName, BigInteger crlNumber) throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    notNull(crlNumber, "crlNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      X509CRLHolder crl = ca.getCrl(crlNumber, MSGID_ca_mgmt);
      if (crl == null) {
        LOG.warn("found no CRL for CA {} and crlNumber {}", caName, crlNumber);
      }
      return crl;
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCrl

  X509CRLHolder getCurrentCrl(String caName) throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    X509Ca ca = getX509Ca(caName);
    try {
      X509CRLHolder crl = ca.getCurrentCrl(MSGID_ca_mgmt);
      if (crl == null) {
        LOG.warn("found no CRL for CA {}", caName);
      }
      return crl;
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCurrentCrl

  ScepResponder getScepResponder(String name) {
    name = toNonBlankLower(name, "name");
    return manager.scepResponders.get(name);
  }

  CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    notNull(serialNumber, "serialNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.getCertWithRevocationInfo(serialNumber);
    } catch (CertificateException | OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCert

  CertWithRevocationInfo getCert(X500Name issuer, BigInteger serialNumber)
      throws CaMgmtException {
    notNull(issuer, "issuer");
    notNull(serialNumber, "serialNumber");

    NameId caId = null;
    for (String name : manager.caInfos.keySet()) {
      CaInfo ca = manager.caInfos.get(name);
      if (issuer.equals(manager.caInfos.get(name).getCert().getSubject())) {
        caId = ca.getIdent();
        break;
      }
    }

    if (caId == null) {
      return null;
    }

    try {
      return manager.certstore.getCertWithRevocationInfo(caId.getId(), serialNumber,
                manager.idNameMap);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCert

  byte[] getCertRequest(String caName, BigInteger serialNumber) throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    notNull(serialNumber, "serialNumber");
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.getCertRequest(serialNumber);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method getCertRequest

  List<CertListInfo> listCertificates(String caName, X500Name subjectPattern, Date validFrom,
      Date validTo, CertListOrderBy orderBy, int numEntries) throws CaMgmtException {
    caName = toNonBlankLower(caName, "caName");
    range(numEntries, "numEntries", 1, 1000);
    X509Ca ca = getX509Ca(caName);
    try {
      return ca.listCerts(subjectPattern, validFrom, validTo, orderBy, numEntries);
    } catch (OperationException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  } // method listCertificates

  void commitNextCrlNo(NameId ca, long nextCrlNo)
      throws OperationException {
    try {
      manager.queryExecutor.commitNextCrlNoIfLess(ca, nextCrlNo);
    } catch (CaMgmtException ex) {
      if (ex.getCause() instanceof DataAccessException) {
        throw new OperationException(ErrorCode.DATABASE_FAILURE, ex.getMessage());
      } else {
        throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
      }
    } catch (RuntimeException ex) {
      throw new OperationException(ErrorCode.SYSTEM_FAILURE, ex.getMessage());
    }
  } // method commitNextCrlNo

  void pulishCertsInQueue() {
    LOG.debug("publishing certificates in PUBLISHQUEUE");
    try {
      for (String name : manager.x509cas.keySet()) {
        X509Ca ca = manager.x509cas.get(name);
        boolean bo = ca.publishCertsInQueue();
        if (bo) {
          LOG.info(" published certificates of CA {} in PUBLISHQUEUE", name);
        } else {
          LOG.error("publishing certificates of CA {} in PUBLISHQUEUE failed", name);
        }
      }
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not publish CertsInQueue");
    }
  }

  void clearPublishQueue(String caName, List<String> publisherNames) throws CaMgmtException {
    assertMasterModeAndSetuped();

    publisherNames = CollectionUtil.toLowerCaseList(publisherNames);

    if (caName == null) {
      if (CollectionUtil.isNotEmpty(publisherNames)) {
        throw new IllegalArgumentException("non-empty publisherNames is not allowed");
      }

      try {
        manager.certstore.clearPublishQueue(null, null);
      } catch (OperationException ex) {
        throw new CaMgmtException(ex.getMessage(), ex);
      }
      return;
    }

    caName = caName.toLowerCase();
    X509Ca ca = manager.x509cas.get(caName);
    if (ca == null) {
      throw new CaMgmtException(concat("could not find CA named ", caName));
    }

    ca.clearPublishQueue(publisherNames);
  } // method clearPublishQueue

  private void assertMasterModeAndSetuped() throws CaMgmtException {
    manager.assertMasterModeAndSetuped();
  }

}
