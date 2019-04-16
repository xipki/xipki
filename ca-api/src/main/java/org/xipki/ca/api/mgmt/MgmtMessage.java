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

package org.xipki.ca.api.mgmt;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.util.X509Util;
import org.xipki.util.Base64;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.InvalidConfException;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 */

public abstract class MgmtMessage {

  public enum MgmtAction {

    addCa,
    addCaAlias,
    addCertprofile,
    addCertprofileToCa,
    addPublisher,
    addPublisherToCa,
    addRequestor,
    addRequestorToCa,
    addSigner,
    addUser,
    addUserToCa,
    changeCa,
    changeCertprofile,
    changePublisher,
    changeRequestor,
    changeSigner,
    changeUser,
    clearPublishQueue,
    exportConf,
    generateCertificate,
    generateCrlOnDemand,
    generateRootCa,
    getAliasesForCa,
    getCa,
    getCaAliasNames,
    getCaHasUsersForUser,
    getCaNameForAlias,
    getCaNames,
    getCaSystemStatus,
    getCert,
    getCertprofile,
    getCertprofileNames,
    getCertprofilesForCa,
    getCertRequest,
    getCrl,
    getCurrentCrl,
    getFailedCaNames,
    getInactiveCaNames,
    getPublisher,
    getPublisherNames,
    getPublishersForCa,
    getRequestor,
    getRequestorNames,
    getRequestorsForCa,
    getSigner,
    getSignerNames,
    getSuccessfulCaNames,
    getSupportedCertprofileTypes,
    getSupportedPublisherTypes,
    getSupportedSignerTypes,
    getUser,
    listCertificates,
    loadConf,
    notifyCaChange,
    refreshTokenForSignerType,
    removeCa,
    removeCaAlias,
    removeCertificate,
    removeCertprofile,
    removeCertprofileFromCa,
    removePublisher,
    removePublisherFromCa,
    removeRequestor,
    removeRequestorFromCa,
    removeSigner,
    removeUser,
    removeUserFromCa,
    republishCertificates,
    restartCaSystem,
    revokeCa,
    revokeCertficate,
    unlockCa,
    unrevokeCa,
    unrevokeCertificate;

    public static final MgmtAction ofName(String str) {
      for (MgmtAction action : MgmtAction.values()) {
        if (action.name().equalsIgnoreCase(str)) {
          return action;
        }
      }

      return null;
    }

  }

  public static class SignerEntryWrapper {

    private String name;

    private String type;

    private String conf;

    private byte[] encodedCert;

    private boolean faulty;

    public SignerEntryWrapper() {
    }

    public SignerEntryWrapper(MgmtEntry.Signer signerEntry) {
      this.name = signerEntry.getName();
      this.type = signerEntry.getType();
      this.conf = signerEntry.getConf();
      this.faulty = signerEntry.isFaulty();
      if (signerEntry.getBase64Cert() != null) {
        this.encodedCert = Base64.decode(signerEntry.getBase64Cert());
      }
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public byte[] getEncodedCert() {
      return encodedCert;
    }

    public void setEncodedCert(byte[] encodedCert) {
      this.encodedCert = encodedCert;
    }

    public String getConf() {
      return conf;
    }

    public boolean isFaulty() {
      return faulty;
    }

    public void setFaulty(boolean faulty) {
      this.faulty = faulty;
    }

    public MgmtEntry.Signer toSignerEntry() {
      String base64Cert = null;
      if (encodedCert != null) {
        base64Cert = Base64.encodeToString(encodedCert);
      }

      MgmtEntry.Signer ret = new MgmtEntry.Signer(name, type, conf, base64Cert);
      ret.setConfFaulty(faulty);
      return ret;
    }
  }

  public static class CaEntryWrapper {

    private NameId ident;

    private CaStatus status;

    private Validity maxValidity;

    private String signerType;

    private String signerConf;

    private String scepControl;

    private String crlControl;

    private String crlSignerName;

    private String cmpControl;

    private String ctLogControl;

    private String cmpResponderName;

    private String scepResponderName;

    private boolean duplicateKeyPermitted;

    private boolean duplicateSubjectPermitted;

    private ProtocolSupport protocolSupport;

    private boolean saveRequest;

    private ValidityMode validityMode = ValidityMode.STRICT;

    private int permission;

    private int expirationPeriod;

    private int keepExpiredCertInDays;

    private String extraControl;

    private CaUris caUris;

    private byte[] certBytes;

    private List<byte[]> certchainBytes;

    private int serialNoBitLen;

    private long nextCrlNumber;

    private int numCrls;

    private CertRevocationInfo revocationInfo;

    public CaEntryWrapper() {
    }

    public CaEntryWrapper(MgmtEntry.Ca caEntry) {
      ident = caEntry.getIdent();
      status = caEntry.getStatus();
      maxValidity = caEntry.getMaxValidity();
      signerType = caEntry.getSignerType();
      signerConf = caEntry.getSignerConf();
      if (caEntry.getScepControl() != null) {
        scepControl = caEntry.getScepControl().getConf();
      }

      if (caEntry.getCrlControl() != null) {
        crlControl = caEntry.getCrlControl().getConf();
      }

      crlSignerName = caEntry.getCrlSignerName();

      if (caEntry.getCmpControl() != null) {
        cmpControl = caEntry.getCmpControl().getConf();
      }

      if (caEntry.getCtLogControl() != null) {
        ctLogControl = caEntry.getCtLogControl().getConf();
      }

      cmpResponderName = caEntry.getCmpResponderName();
      scepResponderName = caEntry.getScepResponderName();
      duplicateKeyPermitted = caEntry.isDuplicateKeyPermitted();
      duplicateSubjectPermitted = caEntry.isDuplicateSubjectPermitted();
      protocolSupport = caEntry.getProtocoSupport();
      saveRequest = caEntry.isSaveRequest();
      validityMode = caEntry.getValidityMode();
      permission = caEntry.getPermission();
      expirationPeriod = caEntry.getExpirationPeriod();
      keepExpiredCertInDays = caEntry.getKeepExpiredCertInDays();

      if (caEntry.getExtraControl() != null) {
        extraControl = caEntry.getExtraControl().getEncoded();
      }

      caUris = caEntry.getCaUris();

      if (caEntry.getCert() != null) {
        try {
          certBytes = caEntry.getCert().getEncoded();
        } catch (CertificateEncodingException ex) {
          throw new IllegalStateException("could not encode certificate", ex);
        }
      }

      if (CollectionUtil.isNonEmpty(caEntry.getCertchain())) {
        this.certchainBytes = new LinkedList<>();
        for (X509Certificate m : caEntry.getCertchain()) {
          try {
            this.certchainBytes.add(m.getEncoded());
          } catch (CertificateEncodingException ex) {
            throw new IllegalStateException("could not encode certificate", ex);
          }
        }
      }

      serialNoBitLen = caEntry.getSerialNoBitLen();
      nextCrlNumber = caEntry.getNextCrlNumber();
      numCrls = caEntry.getNumCrls();
      revocationInfo = caEntry.getRevocationInfo();
    }

    public NameId getIdent() {
      return ident;
    }

    public void setIdent(NameId ident) {
      this.ident = ident;
    }

    public CaStatus getStatus() {
      return status;
    }

    public void setStatus(CaStatus status) {
      this.status = status;
    }

    public Validity getMaxValidity() {
      return maxValidity;
    }

    public void setMaxValidity(Validity maxValidity) {
      this.maxValidity = maxValidity;
    }

    public String getSignerType() {
      return signerType;
    }

    public void setSignerType(String signerType) {
      this.signerType = signerType;
    }

    public String getSignerConf() {
      return signerConf;
    }

    public void setSignerConf(String signerConf) {
      this.signerConf = signerConf;
    }

    public String getScepControl() {
      return scepControl;
    }

    public void setScepControl(String scepControl) {
      this.scepControl = scepControl;
    }

    public String getCrlControl() {
      return crlControl;
    }

    public void setCrlControl(String crlControl) {
      this.crlControl = crlControl;
    }

    public String getCrlSignerName() {
      return crlSignerName;
    }

    public void setCrlSignerName(String crlSignerName) {
      this.crlSignerName = crlSignerName;
    }

    public String getCmpControl() {
      return cmpControl;
    }

    public void setCmpControl(String cmpControl) {
      this.cmpControl = cmpControl;
    }

    public String getCtLogControl() {
      return ctLogControl;
    }

    public void setCtLogControl(String ctLogControl) {
      this.ctLogControl = ctLogControl;
    }

    public String getCmpResponderName() {
      return cmpResponderName;
    }

    public void setCmpResponderName(String cmpResponderName) {
      this.cmpResponderName = cmpResponderName;
    }

    public String getScepResponderName() {
      return scepResponderName;
    }

    public void setScepResponderName(String scepResponderName) {
      this.scepResponderName = scepResponderName;
    }

    public boolean isDuplicateKeyPermitted() {
      return duplicateKeyPermitted;
    }

    public void setDuplicateKeyPermitted(boolean duplicateKeyPermitted) {
      this.duplicateKeyPermitted = duplicateKeyPermitted;
    }

    public boolean isDuplicateSubjectPermitted() {
      return duplicateSubjectPermitted;
    }

    public void setDuplicateSubjectPermitted(boolean duplicateSubjectPermitted) {
      this.duplicateSubjectPermitted = duplicateSubjectPermitted;
    }

    public ProtocolSupport getProtocolSupport() {
      return protocolSupport;
    }

    public void setProtocolSupport(ProtocolSupport protocolSupport) {
      this.protocolSupport = protocolSupport;
    }

    public boolean isSaveRequest() {
      return saveRequest;
    }

    public void setSaveRequest(boolean saveRequest) {
      this.saveRequest = saveRequest;
    }

    public ValidityMode getValidityMode() {
      return validityMode;
    }

    public void setValidityMode(ValidityMode validityMode) {
      this.validityMode = validityMode;
    }

    public int getPermission() {
      return permission;
    }

    public void setPermission(int permission) {
      this.permission = permission;
    }

    public int getExpirationPeriod() {
      return expirationPeriod;
    }

    public void setExpirationPeriod(int expirationPeriod) {
      this.expirationPeriod = expirationPeriod;
    }

    public int getKeepExpiredCertInDays() {
      return keepExpiredCertInDays;
    }

    public void setKeepExpiredCertInDays(int keepExpiredCertInDays) {
      this.keepExpiredCertInDays = keepExpiredCertInDays;
    }

    public String getExtraControl() {
      return extraControl;
    }

    public void setExtraControl(String extraControl) {
      this.extraControl = extraControl;
    }

    public CaUris getCaUris() {
      return caUris;
    }

    public void setCaUris(CaUris caUris) {
      this.caUris = caUris;
    }

    public byte[] getCertBytes() {
      return certBytes;
    }

    public void setCertBytes(byte[] certBytes) {
      this.certBytes = certBytes;
    }

    public List<byte[]> getCertchainBytes() {
      return certchainBytes;
    }

    public void setCertchainBytes(List<byte[]> certchainBytes) {
      this.certchainBytes = certchainBytes;
    }

    public int getSerialNoBitLen() {
      return serialNoBitLen;
    }

    public void setSerialNoBitLen(int serialNoBitLen) {
      this.serialNoBitLen = serialNoBitLen;
    }

    public long getNextCrlNumber() {
      return nextCrlNumber;
    }

    public void setNextCrlNumber(long nextCrlNumber) {
      this.nextCrlNumber = nextCrlNumber;
    }

    public int getNumCrls() {
      return numCrls;
    }

    public void setNumCrls(int numCrls) {
      this.numCrls = numCrls;
    }

    public CertRevocationInfo getRevocationInfo() {
      return revocationInfo;
    }

    public void setRevocationInfo(CertRevocationInfo revocationInfo) {
      this.revocationInfo = revocationInfo;
    }

    public MgmtEntry.Ca toCaEntry()
        throws CertificateException, CaMgmtException, InvalidConfException {
      MgmtEntry.Ca rv = new MgmtEntry.Ca(ident, serialNoBitLen, nextCrlNumber,
                          signerType, signerConf, caUris, numCrls, expirationPeriod);
      if (certBytes != null) {
        rv.setCert(X509Util.parseCert(certBytes));
      }

      if (CollectionUtil.isNonEmpty(certchainBytes)) {
        List<X509Certificate> certchain = new LinkedList<>();
        for (byte[] m : certchainBytes) {
          certchain.add(X509Util.parseCert(m));
        }
        rv.setCertchain(certchain);
      }

      if (cmpControl != null) {
        rv.setCmpControl(new CmpControl(cmpControl));
      }

      rv.setCmpResponderName(cmpResponderName);

      if (crlControl != null) {
        rv.setCrlControl(new CrlControl(crlControl));
      }

      if (ctLogControl != null) {
        rv.setCtLogControl(new CtLogControl(ctLogControl));
      }

      rv.setCrlSignerName(crlSignerName);

      rv.setDuplicateKeyPermitted(duplicateKeyPermitted);
      rv.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

      if (extraControl != null) {
        rv.setExtraControl(new ConfPairs(extraControl));
      }

      rv.setKeepExpiredCertInDays(keepExpiredCertInDays);

      rv.setMaxValidity(maxValidity);

      rv.setNextCrlNumber(nextCrlNumber);
      rv.setPermission(permission);
      rv.setProtocolSupport(protocolSupport);
      rv.setRevocationInfo(revocationInfo);
      rv.setSaveRequest(saveRequest);
      if (scepControl != null) {
        rv.setScepControl(new ScepControl(scepControl));
      }

      rv.setScepResponderName(scepResponderName);
      rv.setSerialNoBitLen(serialNoBitLen);
      rv.setSignerConf(signerConf);
      rv.setStatus(status);
      rv.setValidityMode(validityMode);

      return rv;
    }

  }

}
