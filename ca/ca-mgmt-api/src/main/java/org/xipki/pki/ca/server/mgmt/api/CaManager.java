/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.ca.server.mgmt.api;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.pki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.pki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.pki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaManager {

    String NULL = "NULL";

    CaSystemStatus getCaSystemStatus();

    boolean unlockCa();

    boolean notifyCaChange() throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param publisherNames
     *          Publisher names. Could be {@code null}.
     * @param numThreads
     *          Number of threads
     */
    boolean republishCertificates(String caName, List<String> publisherNames,
            int numThreads) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Could be {@code null}.
     * @param publisherNames
     *          Publisher names. Could be {@code null}.
     */
    boolean clearPublishQueue(String caName, List<String> publisherNames)
            throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean removeCa(String caName) throws CaMgmtException;

    boolean restartCaSystem();

    /**
     *
     * @param aliasName
     *          CA alias name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean addCaAlias(String aliasName, String caName) throws CaMgmtException;

    /**
     *
     * @param aliasName
     *          Alias name. Must not be {@code null}.
     */
    boolean removeCaAlias(String aliasName) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    Set<String> getAliasesForCa(String caName);

    /**
     *
     * @param aliasName
     *          CA alias name. Must not be {@code null}.
     */
    String getCaNameForAlias(String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertprofileNames();

    Set<String> getPublisherNames();

    Set<String> getRequestorNames();

    Set<String> getResponderNames();

    Set<String> getCrlSignerNames();

    Set<String> getCmpControlNames();

    Set<String> getCaNames();

    Set<String> getSuccessfulCaNames();

    Set<String> getFailedCaNames();

    Set<String> getInactiveCaNames();

    /**
     *
     * @param caEntry
     *          CA to be added. Must not be {@code null}.
     */
    boolean addCa(CaEntry caEntry) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return
     */
    CaEntry getCa(String caName);

    /**
     *
     * @param changeCAentry
     *          ChangeCA entry. Must not be {@code null}.
     */
    boolean changeCa(ChangeCaEntry changeCAentry) throws CaMgmtException;

    /**
     *
     * @param profileName
     *          Profile name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean removeCertprofileFromCa(String profileName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param profileName
     *          Profile name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean addCertprofileToCa(String profileName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean removePublisherFromCa(String publisherName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean addPublisherToCa(String publisherName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    Set<String> getCertprofilesForCa(String caName);

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    Set<CaHasRequestorEntry> getRequestorsForCa(String caName);

    /**
     *
     * @param name
     *          Requestor name. Must not be {@code null}.
     */
    CmpRequestorEntry getRequestor(String name);

    /**
     *
     * @param dbEntry
     *          Requestor entry. Must not be {@code null}.
     */
    boolean addRequestor(CmpRequestorEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param requestorName
     *          Requestor name. Must not be {@code null}.
     */
    boolean removeRequestor(String requestorName) throws CaMgmtException;

    /**
     *
     * @param name
     *          Requestor naem. Must not be {@code null}.
     * @param base64Cert
     *          Base64 encoded certificate of the requestor's certificate.
     *          Must not be {@code null}.
     */
    boolean changeRequestor(String name, String base64Cert)
            throws CaMgmtException;

    /**
     *
     * @param requestorName
     *          Requestor name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean removeRequestorFromCa(String requestorName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param requestor
     *          Requestor name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean addRequestorToCa(CaHasRequestorEntry requestor, String caName)
            throws CaMgmtException;

    /**
     *
     * @param userName
     *          User name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean removeUserFromCa(String userName, String caName)
            throws CaMgmtException;

    /**
     *
     * @param user
     *          User entry. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean addUserToCa(CaHasUserEntry user, String caName)
            throws CaMgmtException;

    /**
     * Returns map between CA name an CaHasUserEntry for given user.
     * @param user User
     * @return map between CA name and CaHasUserEntry for given user.
     * @throws CaMgmtException If error occurs.
     */
    Map<String, CaHasUserEntry> getCaHasUsers(String user)
            throws CaMgmtException;

    /**
     *
     * @param profileName
     *          certificate profile name. Must not be {@code null}.
     */
    CertprofileEntry getCertprofile(String profileName);

    /**
     *
     * @param profileName
     *          certificate profile name. Must not be {@code null}.
     */
    boolean removeCertprofile(String profileName) throws CaMgmtException;

    /**
     *
     * @param name
     *          name of the certificate profile to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     */
    boolean changeCertprofile(String name, String type, String conf)
            throws CaMgmtException;

    /**
     *
     * @param dbEntry
     *          Certificate profile entry. Must not be {@code null}.
     */
    boolean addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param dbEntry
     *          Responder entry. Must not be {@code null}.
     */
    boolean addResponder(CmpResponderEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param name
     *          Responder name. Must not be {@code null}.
     */
    boolean removeResponder(String name) throws CaMgmtException;

    /**
     *
     * @param name
     *          Responder name. Must not be {@code null}.
     */
    CmpResponderEntry getResponder(String name);

    /**
     *
     * @param name
     *          name of the responder to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     * @param base64Cert
     *          Base64 encoded certificate of the responder. {@code null} indicates no change.
     */
    boolean changeResponder(String name, String type, String conf, String base64Cert)
            throws CaMgmtException;

    /**
     *
     * @param dbEntry
     *          CRL signer entry. Must not be {@code null}.
     */
    boolean addCrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param crlSignerName
     *          Name of the CRL signer. Must not be {@code null}.
     */
    boolean removeCrlSigner(String crlSignerName) throws CaMgmtException;

    /**
     *
     * @param dbEntry
     *          CRL signer entry. Must not be {@code null}.
     */
    boolean changeCrlSigner(X509ChangeCrlSignerEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param name
     *          CRL signer name. Must not be {@code null}.
     * @return
     */
    X509CrlSignerEntry getCrlSigner(String name);

    /**
     *
     * @param dbEntry
     *          Publisher entry.
     */
    boolean addPublisher(PublisherEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    List<PublisherEntry> getPublishersForCa(String caName);

    /**
     *
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     */
    PublisherEntry getPublisher(String publisherName);

    /**
     *
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     */
    boolean removePublisher(String publisherName) throws CaMgmtException;

    /**
     *
     * @param name
     *          name of the publisher to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     */
    boolean changePublisher(String name, String type, String conf)
            throws CaMgmtException;

    /**
     *
     * @param name
     *          CMP control name.
     */
    CmpControlEntry getCmpControl(String name);

    /**
     *
     * @param dbEntry
     *          CMP control entry. Must not be {@code null}.
     */
    boolean addCmpControl(CmpControlEntry dbEntry) throws CaMgmtException;

    /**
     *
     * @param name
     *          CMP control name. Must not be {@code null}.
     */
    boolean removeCmpControl(String name) throws CaMgmtException;

    /**
     *
     * @param name
     *          name of the CMP control to be changed. Must not be {@code null}.
     * @param conf
     *          Configuration to be changed. Must not be {@code null}.
     */
    boolean changeCmpControl(String name, String conf) throws CaMgmtException;

    Set<String> getEnvParamNames();

    /**
     *
     * @param name
     *          Environment name. Must not be {@code null}.
     */
    String getEnvParam(String name);

    /**
     *
     * @param name
     *          Environment name. Must not be {@code null}.
     * @param value
     *          Environment value. Must not be {@code null}.
     */
    boolean addEnvParam(String name, String value) throws CaMgmtException;

    /**
     *
     * @param envParamName
     *          Environment name. Must not be {@code null}.
     */
    boolean removeEnvParam(String envParamName) throws CaMgmtException;

    /**
     *
     * @param name
     *          name of the CMP control to be changed. Must not be {@code null}.
     * @param value
     *          Environment value to be changed. Must not be {@code null}.
     */
    boolean changeEnvParam(String name, String value) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param revocationInfo
     *          Revocation information. Must not be {@code null}.
     * @return
     * @throws CaMgmtException
     */
    boolean revokeCa(String caName, CertRevocationInfo revocationInfo)
            throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    boolean unrevokeCa(String caName) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @param reason
     *          Revocation reason. Must not be {@code null}.
     * @param invalidityTime
     *          Invalidity time. Could be {@code null}.
     */
    boolean revokeCertificate(String caName, BigInteger serialNumber,
            CrlReason reason, Date invalidityTime) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     */
    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     */
    boolean removeCertificate(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param profileName
     *          Name of the certificate profile. Must not be {@code null}.
     * @param encodedCsr
     *          DER-encoded CSR. Must not be {@code null}.
     * @param notBefore
     *          NotBefore. Could be {@code null}.
     * @param notAfter
     *          NotAfter. Could be {@code null}.
     */
    X509Certificate generateCertificate(String caName, String profileName,
            byte[] encodedCsr, Date notBefore, Date notAfter)
            throws CaMgmtException;

    /**
     *
     * @param caEntry
     *          CA entry. Must not be {@code null}.
     * @param certprofileName
     *          Profile name of the root CA certificate. Must not be {@code null}.
     * @param encodedCsr
     *          DER-encoded CSR. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Could be {@code null}.
     * @return
     * @throws CaMgmtException
     */
    X509Certificate generateRootCa(X509CaEntry caEntry, String certprofileName,
            byte[] encodedCsr, BigInteger serialNumber) throws CaMgmtException;

    /**
     *
     * @param userEntry
     *          AddUser entry. Must not be {@code null}.
     */
    boolean addUser(AddUserEntry userEntry) throws CaMgmtException;

    /**
     *
     * @param userEntry
     *          User change entry. Must not be {@code null}.
     */
    boolean changeUser(ChangeUserEntry userEntry) throws CaMgmtException;

    /**
     *
     * @param username
     *          User name. Must not be {@code null}.
     */
    boolean removeUser(String username) throws CaMgmtException;

    /**
     *
     * @param username
     *          User name. Must not be {@code null}.
     */
    UserEntry getUser(String username) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    X509CRL generateCrlOnDemand(String caName) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param crlNumber
     *          CRL number. Must not be {@code null}.
     */
    X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     */
    X509CRL getCurrentCrl(String caName) throws CaMgmtException;

    /**
     *
     * @param scepEntry
     *          SCEP entry. Must not be {@code null}.
     */
    boolean addScep(ScepEntry scepEntry) throws CaMgmtException;

    /**
     *
     * @param name
     *          SCEP name. Must not be {@code null}.
     */
    boolean removeScep(String name) throws CaMgmtException;

    /**
     *
     * @param scepEntry
     *          SCEP change information. Must not be {@code null}.
     */
    boolean changeScep(ChangeScepEntry scepEntry) throws CaMgmtException;

    Set<String> getScepNames();

    /**
     *
     * @param name
     *          SCEP name. Must not be {@code null}.
     */
    ScepEntry getScepEntry(String name) throws CaMgmtException;

    /**
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @return
     * @throws CaMgmtException
     */
    CertWithStatusInfo getCert(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     * @param conf
     *          Configuration of the CA system. Must not be {@code null}.
     * @since 2.1.0
     */
    boolean loadConf(CaConf conf) throws CaMgmtException;

    /**
     * @param zipFilename
     *          Where to save the exported ZIP file. Must be {@code null}.
     * @param caNames
     *          List of the names of CAs to be exported. {@code null} to export all CAs.
     *
     * @since 2.1.0
     */
    boolean exportConf(String zipFilename, List<String> caNames)
            throws CaMgmtException, IOException;

    /**
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param subjectPattern
     *          Subject pattern. Could be {@code null}.
     * @param validFrom
     *          Valid from. Could be {@code null}.
     * @param validTo
     *          Valid to. Could be {@code null}.
     * @param orderBy
     *          How the result is ordered. Could be {@code null}.
     * @since 2.1.0
     */
    List<CertListInfo> listCertificates(String caName, X500Name subjectPattern,
            Date validFrom, Date validTo, CertListOrderBy orderBy,
            int numEntries) throws CaMgmtException;

    /**
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @since 2.1.0
     */
    byte[] getCertRequest(String caName, BigInteger serialNumber)
            throws CaMgmtException;

}
