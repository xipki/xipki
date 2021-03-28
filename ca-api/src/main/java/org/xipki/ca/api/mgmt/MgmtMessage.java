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

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.util.*;

import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;

/**
 * CA Management message via the REST API.
 *
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
    restartCa,
    restartCaSystem,
    revokeCa,
    revokeCertficate,
    unlockCa,
    unrevokeCa,
    unrevokeCertificate;

    public static MgmtAction ofName(String str) {
      for (MgmtAction action : MgmtAction.values()) {
        if (action.name().equalsIgnoreCase(str)) {
          return action;
        }
      }

      return null;
    }

  } // class MgmtAction

  public static class SignerEntryWrapper {

    private String name;

    private String type;

    private String conf;

    private byte[] encodedCert;

    private boolean faulty;

    public SignerEntryWrapper() {
    }

    public SignerEntryWrapper(SignerEntry signerEntry) {
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

    public SignerEntry toSignerEntry() {
      String base64Cert = null;
      if (encodedCert != null) {
        base64Cert = Base64.encodeToString(encodedCert);
      }

      SignerEntry ret = new SignerEntry(name, type, conf, base64Cert);
      ret.setConfFaulty(faulty);
      return ret;
    }
  } // class SignerEntryWrapper

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

    private String ctlogControl;

    private String dhpocControl;

    private String revokeSuspended;

    private String cmpResponderName;

    private String scepResponderName;

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

    private int serialNoLen;

    private long nextCrlNumber;

    private int numCrls;

    private CertRevocationInfo revocationInfo;

    public CaEntryWrapper() {
    }

    public CaEntryWrapper(CaEntry caEntry) {
      caUris = caEntry.getCaUris();

      if (caEntry.getCert() != null) {
        certBytes = caEntry.getCert().getEncoded();
      }

      if (CollectionUtil.isNotEmpty(caEntry.getCertchain())) {
        this.certchainBytes = new LinkedList<>();
        for (X509Cert m : caEntry.getCertchain()) {
          this.certchainBytes.add(m.getEncoded());
        }
      }

      if (caEntry.getCmpControl() != null) {
        cmpControl = caEntry.getCmpControl().getConf();
      }

      cmpResponderName = caEntry.getCmpResponderName();

      if (caEntry.getCrlControl() != null) {
        crlControl = caEntry.getCrlControl().getConf();
      }

      crlSignerName = caEntry.getCrlSignerName();

      if (caEntry.getCtlogControl() != null) {
        ctlogControl = caEntry.getCtlogControl().getConf();
      }

      dhpocControl = caEntry.getDhpocControl();
      expirationPeriod = caEntry.getExpirationPeriod();
      if (caEntry.getExtraControl() != null) {
        extraControl = caEntry.getExtraControl().getEncoded();
      }

      ident = caEntry.getIdent();
      keepExpiredCertInDays = caEntry.getKeepExpiredCertInDays();
      maxValidity = caEntry.getMaxValidity();
      nextCrlNumber = caEntry.getNextCrlNumber();
      numCrls = caEntry.getNumCrls();
      permission = caEntry.getPermission();
      protocolSupport = caEntry.getProtocoSupport();
      revocationInfo = caEntry.getRevocationInfo();
      if (caEntry.getRevokeSuspendedControl() != null) {
        revokeSuspended = caEntry.getRevokeSuspendedControl().getConf();
      }
      saveRequest = caEntry.isSaveRequest();
      if (caEntry.getScepControl() != null) {
        scepControl = caEntry.getScepControl().getConf();
      }
      scepResponderName = caEntry.getScepResponderName();

      serialNoLen = caEntry.getSerialNoLen();
      signerConf = caEntry.getSignerConf();
      signerType = caEntry.getSignerType();

      status = caEntry.getStatus();

      validityMode = caEntry.getValidityMode();
    } // method constructor

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

    public String getRevokeSuspended() {
      return revokeSuspended;
    }

    public void setRevokeSuspended(String revokeSuspended) {
      this.revokeSuspended = revokeSuspended;
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

    public String getCtlogControl() {
      return ctlogControl;
    }

    public void setCtlogControl(String ctlogControl) {
      this.ctlogControl = ctlogControl;
    }

    public String getDhpocControl() {
      return dhpocControl;
    }

    public void setDhpocControl(String dhpocControl) {
      this.dhpocControl = dhpocControl;
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

    public int getSerialNoLen() {
      return serialNoLen;
    }

    public void setSerialNoLen(int serialNoLen) {
      this.serialNoLen = serialNoLen;
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

    public CaEntry toCaEntry()
        throws CertificateException, CaMgmtException, InvalidConfException {
      CaEntry rv = new CaEntry(ident, serialNoLen, nextCrlNumber,
                          signerType, signerConf, caUris, numCrls, expirationPeriod);
      if (certBytes != null) {
        rv.setCert(X509Util.parseCert(certBytes));
      }

      if (CollectionUtil.isNotEmpty(certchainBytes)) {
        List<X509Cert> certchain = new LinkedList<>();
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

      if (ctlogControl != null) {
        rv.setCtlogControl(new CtlogControl(ctlogControl));
      }

      rv.setCrlSignerName(crlSignerName);

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

      if (revokeSuspended != null) {
        rv.setRevokeSuspendedControl(new RevokeSuspendedControl(revokeSuspended));
      }

      rv.setScepResponderName(scepResponderName);
      rv.setSerialNoLen(serialNoLen);
      rv.setSignerConf(signerConf);
      rv.setStatus(status);
      rv.setValidityMode(validityMode);

      rv.setDhpocControl(dhpocControl);

      return rv; // method toCaEntry
    }

  } // class CaEntryWrapper

}
