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

import org.xipki.ca.api.mgmt.entry.*;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

/**
 * CA Management request via the REST API.
 *
 * @author Lijun Liao
 */

public abstract class MgmtRequest extends MgmtMessage {

  public static class AddCaAlias extends CaNameRequest {

    private String aliasName;

    public String getAliasName() {
      return aliasName;
    }

    public void setAliasName(String aliasName) {
      this.aliasName = aliasName;
    }

  } // class AddCaAlias

  public static class AddCa extends MgmtRequest {

    private CaEntryWrapper caEntry;

    public CaEntryWrapper getCaEntry() {
      return caEntry;
    }

    public void setCaEntry(CaEntryWrapper caEntry) {
      this.caEntry = caEntry;
    }

  } // class AddCa

  public static class AddCertprofile extends MgmtRequest {

    private CertprofileEntry certprofileEntry;

    public CertprofileEntry getCertprofileEntry() {
      return certprofileEntry;
    }

    public void setCertprofileEntry(CertprofileEntry certprofileEntry) {
      this.certprofileEntry = certprofileEntry;
    }

  } // class AddCertprofile

  public static class AddCertprofileToCa extends CaNameRequest {

    private String profileName;

    public String getProfileName() {
      return profileName;
    }

    public void setProfileName(String profileName) {
      this.profileName = profileName;
    }

  } // class AddCertprofileToCa

  public static class AddPublisher extends MgmtRequest {

    private PublisherEntry publisherEntry;

    public PublisherEntry getPublisherEntry() {
      return publisherEntry;
    }

    public void setPublisherEntry(PublisherEntry publisherEntry) {
      this.publisherEntry = publisherEntry;
    }

  } // class AddPublisher

  public static class AddPublisherToCa extends CaNameRequest {

    private String publisherName;

    public String getPublisherName() {
      return publisherName;
    }

    public void setPublisherName(String publisherName) {
      this.publisherName = publisherName;
    }

  } // class AddPublisherToCa

  public static class AddRequestor extends MgmtRequest {

    private RequestorEntry requestorEntry;

    public RequestorEntry getRequestorEntry() {
      return requestorEntry;
    }

    public void setRequestorEntry(RequestorEntry requestorEntry) {
      this.requestorEntry = requestorEntry;
    }

  } // class AddRequestor

  public static class AddRequestorToCa extends CaNameRequest {

    private CaHasRequestorEntry requestor;

    public CaHasRequestorEntry getRequestor() {
      return requestor;
    }

    public void setRequestor(CaHasRequestorEntry requestor) {
      this.requestor = requestor;
    }

  } // class AddRequestorToCa

  public static class AddSigner extends MgmtRequest {

    private SignerEntryWrapper signerEntry;

    public SignerEntryWrapper getSignerEntry() {
      return signerEntry;
    }

    public void setSignerEntry(SignerEntryWrapper signerEntry) {
      this.signerEntry = signerEntry;
    }

  } // class AddSigner

  public static class AddUser extends MgmtRequest {

    private AddUserEntry addUserEntry;

    public AddUserEntry getAddUserEntry() {
      return addUserEntry;
    }

    public void setAddUserEntry(AddUserEntry addUserEntry) {
      this.addUserEntry = addUserEntry;
    }

  } // class AddUser

  public static class AddUserToCa extends CaNameRequest {

    private CaHasUserEntry user;

    public CaHasUserEntry getUser() {
      return user;
    }

    public void setUser(CaHasUserEntry user) {
      this.user = user;
    }

  } // class AddUserToCa

  public abstract static class CaNameRequest extends MgmtRequest {

    private String caName;

    public String getCaName() {
      return caName;
    }

    public void setCaName(String caName) {
      this.caName = caName;
    }

  } // class CaNameRequest

  public static class ChangeCa extends MgmtRequest {

    private ChangeCaEntry changeCaEntry;

    public ChangeCaEntry getChangeCaEntry() {
      return changeCaEntry;
    }

    public void setChangeCaEntry(ChangeCaEntry changeCaEntry) {
      this.changeCaEntry = changeCaEntry;
    }

  } // class ChangeCa

  public static class ChangeSigner extends MgmtRequest {

    private String name;

    private String type;

    private String conf;

    private String base64Cert;

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

    public String getConf() {
      return conf;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public String getBase64Cert() {
      return base64Cert;
    }

    public void setBase64Cert(String base64Cert) {
      this.base64Cert = base64Cert;
    }

  } // class ChangeSigner

  public static class ChangeTypeConfEntity extends MgmtRequest {

    private String name;

    private String type;

    private String conf;

    public ChangeTypeConfEntity() {
    }

    public ChangeTypeConfEntity(String name, String type, String conf) {
      this.name = name;
      this.type = type;
      this.conf = conf;
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

    public String getConf() {
      return conf;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

  } // class ChangeTypeConfEntity

  public static class ChangeUser extends MgmtRequest {

    private ChangeUserEntry changeUserEntry;

    public ChangeUserEntry getChangeUserEntry() {
      return changeUserEntry;
    }

    public void setChangeUserEntry(ChangeUserEntry changeUserEntry) {
      this.changeUserEntry = changeUserEntry;
    }

  } // class ChangeUser

  public static class ClearPublishQueue extends CaNameRequest {

    private List<String> publisherNames;

    public List<String> getPublisherNames() {
      return publisherNames;
    }

    public void setPublisherNames(List<String> publisherNames) {
      this.publisherNames = publisherNames;
    }

  } // class ClearPublishQueue

  public static class ExportConf extends MgmtRequest {

    private List<String> caNames;

    public List<String> getCaNames() {
      return caNames;
    }

    public void setCaNames(List<String> caNames) {
      this.caNames = caNames;
    }

  } // class ExportConf

  public static class GenerateCertificate extends CaNameRequest {

    private String profileName;

    private byte[] encodedCsr;

    private Date notBefore;

    private Date notAfter;

    public String getProfileName() {
      return profileName;
    }

    public void setProfileName(String profileName) {
      this.profileName = profileName;
    }

    public byte[] getEncodedCsr() {
      return encodedCsr;
    }

    public void setEncodedCsr(byte[] encodedCsr) {
      this.encodedCsr = encodedCsr;
    }

    public Date getNotBefore() {
      return notBefore;
    }

    public void setNotBefore(Date notBefore) {
      this.notBefore = notBefore;
    }

    public Date getNotAfter() {
      return notAfter;
    }

    public void setNotAfter(Date notAfter) {
      this.notAfter = notAfter;
    }

  } // class GenerateCertificate

  public static class GenerateRootCa extends MgmtRequest {

    private CaEntryWrapper caEntry;

    private String certprofileName;

    private String subject;

    private String serialNumber;

    public CaEntryWrapper getCaEntry() {
      return caEntry;
    }

    public void setCaEntry(CaEntryWrapper caEntry) {
      this.caEntry = caEntry;
    }

    public String getCertprofileName() {
      return certprofileName;
    }

    public void setCertprofileName(String certprofileName) {
      this.certprofileName = certprofileName;
    }

    public String getSubject() {
      return subject;
    }

    public void setSubject(String subject) {
      this.subject = subject;
    }

    public String getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
      this.serialNumber = serialNumber;
    }

  } // class GenerateRootCa

  public static class GetCert extends MgmtRequest {

    /**
     * CA name. Either caName or issuerDn must be set.
     */
    private String caName;

    /**
     * Issuer DN. Either caName or issuerDn must be set.
     */
    private byte[] encodedIssuerDn;

    private BigInteger serialNumber;

    public String getCaName() {
      return caName;
    }

    public void setCaName(String caName) {
      this.caName = caName;
    }

    public byte[] getEncodedIssuerDn() {
      return encodedIssuerDn;
    }

    public void setEncodedIssuerDn(byte[] encodedIssuerDn) {
      this.encodedIssuerDn = encodedIssuerDn;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
      this.serialNumber = serialNumber;
    }

  } // class GetCert

  public static class GetCertRequest extends MgmtRequest {

    private String caName;

    private BigInteger serialNumber;

    public String getCaName() {
      return caName;
    }

    public void setCaName(String caName) {
      this.caName = caName;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
      this.serialNumber = serialNumber;
    }

  } // class GetCertRequest

  public static class GetCrl extends CaNameRequest {

    private BigInteger crlNumber;

    public BigInteger getCrlNumber() {
      return crlNumber;
    }

    public void setCrlNumber(BigInteger crlNumber) {
      this.crlNumber = crlNumber;
    }

  } // class GetCrl

  public static class ListCertificates extends CaNameRequest {

    private byte[] encodedSubjectDnPattern;

    private Date validFrom;

    private Date validTo;

    private CertListOrderBy orderBy;

    private int numEntries;

    public byte[] getEncodedSubjectDnPattern() {
      return encodedSubjectDnPattern;
    }

    public void setEncodedSubjectDnPattern(byte[] encodedSubjectDnPattern) {
      this.encodedSubjectDnPattern = encodedSubjectDnPattern;
    }

    public Date getValidFrom() {
      return validFrom;
    }

    public void setValidFrom(Date validFrom) {
      this.validFrom = validFrom;
    }

    public Date getValidTo() {
      return validTo;
    }

    public void setValidTo(Date validTo) {
      this.validTo = validTo;
    }

    public CertListOrderBy getOrderBy() {
      return orderBy;
    }

    public void setOrderBy(CertListOrderBy orderBy) {
      this.orderBy = orderBy;
    }

    public int getNumEntries() {
      return numEntries;
    }

    public void setNumEntries(int numEntries) {
      this.numEntries = numEntries;
    }

  } // class ListCertificates

  public static class LoadConf extends MgmtRequest {

    private byte[] confBytes;

    public byte[] getConfBytes() {
      return confBytes;
    }

    public void setConfBytes(byte[] confBytes) {
      this.confBytes = confBytes;
    }

  } // class LoadConf

  public static class Name extends MgmtRequest {

    private String name;

    public Name() {
    }

    public Name(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

  } // class Name

  public static class RemoveCertificate extends CaNameRequest {

    private BigInteger serialNumber;

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
      this.serialNumber = serialNumber;
    }

  } // class RemoveCertificate

  public static class RemoveEntityFromCa extends CaNameRequest {

    private String entityName;

    public String getEntityName() {
      return entityName;
    }

    public void setEntityName(String entityName) {
      this.entityName = entityName;
    }

  } // class RemoveEntityFromCa

  public static class RepublishCertificates extends CaNameRequest {

    private List<String> publisherNames;

    private int numThreads;

    public List<String> getPublisherNames() {
      return publisherNames;
    }

    public void setPublisherNames(List<String> publisherNames) {
      this.publisherNames = publisherNames;
    }

    public int getNumThreads() {
      return numThreads;
    }

    public void setNumThreads(int numThreads) {
      this.numThreads = numThreads;
    }

  } // class RepublishCertificates

  public static class RevokeCa extends CaNameRequest {

    private CertRevocationInfo revocationInfo;

    public CertRevocationInfo getRevocationInfo() {
      return revocationInfo;
    }

    public void setRevocationInfo(CertRevocationInfo revocationInfo) {
      this.revocationInfo = revocationInfo;
    }

  } // class RevokeCa

  public static class RevokeCertificate extends CaNameRequest {

    private BigInteger serialNumber;

    private CrlReason reason;

    private Date invalidityTime;

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
      this.serialNumber = serialNumber;
    }

    public CrlReason getReason() {
      return reason;
    }

    public void setReason(CrlReason reason) {
      this.reason = reason;
    }

    public Date getInvalidityTime() {
      return invalidityTime;
    }

    public void setInvalidityTime(Date invalidityTime) {
      this.invalidityTime = invalidityTime;
    }

  } // class RevokeCertificate

  public static class UnrevokeCertificate extends CaNameRequest {

    private BigInteger serialNumber;

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
      this.serialNumber = serialNumber;
    }

  } // class UnrevokeCertificate

  public static class TokenInfoP11 extends MgmtRequest {

    private boolean verbose;

    private String moduleName;

    private Integer slotIndex;

    public TokenInfoP11(String moduleName, Integer slotIndex, boolean verbose) {
      this.moduleName = moduleName;
      this.slotIndex = slotIndex;
      this.verbose = verbose;
    }

    public boolean isVerbose() {
      return verbose;
    }

    public void setVerbose(boolean verbose) {
      this.verbose = verbose;
    }

    public String getModuleName() {
      return moduleName;
    }

    public void setModuleName(String moduleName) {
      this.moduleName = moduleName;
    }

    public Integer getSlotIndex() {
      return slotIndex;
    }

    public void setSlotIndex(Integer slotIndex) {
      this.slotIndex = slotIndex;
    }
  }

}
