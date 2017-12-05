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

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.xipki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.ca.server.mgmt.api.x509.X509CrlSignerEntry;
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
     * Republishes certificates of the CA {@code caName} to the publishers {@code publisherNames}.
     * 
     * @param caName
     *          CA name. Could be {@code null}.
     * @param publisherNames
     *          Publisher names. Could be {@code null}.
     * @param numThreads
     *          Number of threads
     * @return whether the publish is successful
     * @throws CaMgmtException
     *          if error occurs.
     * 
     */
    boolean republishCertificates(String caName, List<String> publisherNames,
            int numThreads) throws CaMgmtException;

    /**
     * Clear the publish queue for the CA {@code caName} and publishers {@code publisherNames}.
     * 
     * @param caName
     *          CA name. Could be {@code null}.
     * @param publisherNames
     *          Publisher names. Could be {@code null}.
     * @return whether the cleanup is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean clearPublishQueue(String caName, List<String> publisherNames)
            throws CaMgmtException;

    /**
     * Removes the CA {@code caName} from the system.
     * 
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the remove is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCa(String caName) throws CaMgmtException;

    boolean restartCaSystem();

    /**
     * Adds the alias {@code aliasName} to the given CA {@code caName}.
     *
     * @param aliasName
     *          CA alias name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the addition is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCaAlias(String aliasName, String caName) throws CaMgmtException;

    /**
     * Remove the alias {@code aliasName}.
     * 
     * @param aliasName
     *          Alias name. Must not be {@code null}.
     * @return whether the remove is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCaAlias(String aliasName) throws CaMgmtException;

    /**
     * Gets the aliases of the given CA {@code caName}.
     * 
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the aliases of the given CA.
     */
    Set<String> getAliasesForCa(String caName);

    /**
     * Gets the CA name for the alias {@code aliasName}.
     *
     * @param aliasName
     *          CA alias name. Must not be {@code null}.
     * @return the aliases of the given CA.
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
     * Adds a CA
     * @param caEntry
     *          CA to be added. Must not be {@code null}.
     * @return whether the addition is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCa(CaEntry caEntry) throws CaMgmtException;

    /**
     * Gets the CA named {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the CaEntry
     */
    CaEntry getCa(String caName);

    /**
     * Changes a CA.
     *
     * @param changeCAentry
     *          ChangeCA entry. Must not be {@code null}.
     * @return whether the change is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeCa(ChangeCaEntry changeCAentry) throws CaMgmtException;

    /**
     * Removes the support of the certProfile {@code profileName} from the CA {@code caName}.
     * 
     * @param profileName
     *          Profile name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the remove is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCertprofileFromCa(String profileName, String caName)
            throws CaMgmtException;

    /**
     * Add the certificate profile {@code profileName} the the CA {@code caName}.
     * @param profileName
     *          Profile name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the addition is successful
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCertprofileToCa(String profileName, String caName)
            throws CaMgmtException;

    /**
     * Removes publisher {@code publisherName} from the CA {@code caName}.
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removePublisherFromCa(String publisherName, String caName)
            throws CaMgmtException;

    /**
     * Adds publisher {@code publisherName} to CA {@code caName}.
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addPublisherToCa(String publisherName, String caName)
            throws CaMgmtException;

    /**
     * Returns the CertProfile names supported by the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the CertProfile names.
     */
    Set<String> getCertprofilesForCa(String caName);

    /**
     * Returns the Requests supported by the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the requestors.
     */
    Set<CaHasRequestorEntry> getRequestorsForCa(String caName);

    /**
     * Returns the requestor named {@code name}.
     * @param name
     *          Requestor name. Must not be {@code null}.
     * @return the requestor.
     */
    CmpRequestorEntry getRequestor(String name);

    /**
     * Adds requstor.
     * @param dbEntry
     *          Requestor entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addRequestor(CmpRequestorEntry dbEntry) throws CaMgmtException;

    /**
     * Removes requestor named {@code requestorName}.
     * @param requestorName
     *          Requestor name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeRequestor(String requestorName) throws CaMgmtException;

    /**
     * Chagnes the requestor {@code name}.
     * @param name
     *          Requestor name. Must not be {@code null}.
     * @param base64Cert
     *          Base64 encoded certificate of the requestor's certificate.
     *          Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeRequestor(String name, String base64Cert)
            throws CaMgmtException;

    /**
     * Removes the requestor {@code requestorName} from the CA {@code caName}.
     * @param requestorName
     *          Requestor name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeRequestorFromCa(String requestorName, String caName)
            throws CaMgmtException;

    /**
     * Adds the requestor {@code requestorName} to the CA {@code caName}.
     * @param requestor
     *          Requestor name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addRequestorToCa(CaHasRequestorEntry requestor, String caName)
            throws CaMgmtException;

    /**
     * Removes the user {@code userName} from the CA {@code caName}.
     * @param userName
     *          User name. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeUserFromCa(String userName, String caName)
            throws CaMgmtException;

    /**
     * Adds the user {@code userName} from the CA {@code caName}.
     * @param user
     *          User entry. Must not be {@code null}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addUserToCa(CaHasUserEntry user, String caName)
            throws CaMgmtException;

    /**
     * Returns map between CA name an CaHasUserEntry for given user.
     * @param user User
     * @return map between CA name and CaHasUserEntry for given user.
     * @throws CaMgmtException
     *          if error occurs.
     */
    Map<String, CaHasUserEntry> getCaHasUsers(String user)
            throws CaMgmtException;

    /**
     * Returns the certificate profile named {@code profileName}.
     * @param profileName
     *          certificate profile name. Must not be {@code null}.
     * @return the profile
     */
    CertprofileEntry getCertprofile(String profileName);

    /**
     * Removes the certificate profile {@code profileName}.
     * @param profileName
     *          certificate profile name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCertprofile(String profileName) throws CaMgmtException;

    /**
     * Changes the certificate profile {@code name}.
     * @param name
     *          name of the certificate profile to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeCertprofile(String name, String type, String conf)
            throws CaMgmtException;

    /**
     * Adds a certificate profile.
     * @param dbEntry
     *          Certificate profile entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCertprofile(CertprofileEntry dbEntry) throws CaMgmtException;

    /**
     * Adds a responder.
     * @param dbEntry
     *          Responder entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addResponder(CmpResponderEntry dbEntry) throws CaMgmtException;

    /**
     * Removes the responder named {@code name}.
     * @param name
     *          Responder name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeResponder(String name) throws CaMgmtException;

    /**
     * Returns the responder named {@code name}.
     * @param name
     *          Responder name. Must not be {@code null}.
     * @return the responder.
     */
    CmpResponderEntry getResponder(String name);

    /**
     * Changes the responder {@code name}.
     * @param name
     *          name of the responder to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     * @param base64Cert
     *          Base64 encoded certificate of the responder. {@code null} indicates no change.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeResponder(String name, String type, String conf, String base64Cert)
            throws CaMgmtException;

    /**
     * Adds a CRL signer.
     * @param dbEntry
     *          CRL signer entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCrlSigner(X509CrlSignerEntry dbEntry) throws CaMgmtException;

    /**
     * Remove the CRL signer {@code crlSignerName}.
     * @param crlSignerName
     *          Name of the CRL signer. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCrlSigner(String crlSignerName) throws CaMgmtException;

    /**
     * Changes the CRL signer.
     * @param dbEntry
     *          CRL signer entry. Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeCrlSigner(X509ChangeCrlSignerEntry dbEntry) throws CaMgmtException;

    /**
     * Returns the CRL signer named {@code name}.
     * @param name
     *          CRL signer name. Must not be {@code null}.
     * @return the CRL Signer
     */
    X509CrlSignerEntry getCrlSigner(String name);

    /**
     * Adds a publisher.
     * @param dbEntry
     *          Publisher entry.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addPublisher(PublisherEntry dbEntry) throws CaMgmtException;

    /**
     * Returns publishers for the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return publishers for the given CA.
     */
    List<PublisherEntry> getPublishersForCa(String caName);

    /**
     * Returns the publisher.
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @return the publisher.
     */
    PublisherEntry getPublisher(String publisherName);

    /**
     * Removes the publisher {@code publisherName}.
     * @param publisherName
     *          Publisher name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removePublisher(String publisherName) throws CaMgmtException;

    /**
     * Changes the publisher {@code name}.
     * @param name
     *          name of the publisher to be changed. Must not be {@code null}.
     * @param type
     *          Type to be changed. {@code null} indicates no change.
     * @param conf
     *          Configuration to be changed. {@code null} indicates no change.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changePublisher(String name, String type, String conf)
            throws CaMgmtException;

    /**
     * Returns the CMP control.
     * @param name
     *          CMP control name.
     * @return the CMP control.
     */
    CmpControlEntry getCmpControl(String name);

    /**
     * Adds a SCEP contrl.
     * @param dbEntry
     *          CMP control entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addCmpControl(CmpControlEntry dbEntry) throws CaMgmtException;

    /**
     * Remove the CMP control {@code name}.
     * @param name
     *          CMP control name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCmpControl(String name) throws CaMgmtException;

    /**
     * Changes the CMP control {@code name}.
     * @param name
     *          name of the CMP control to be changed. Must not be {@code null}.
     * @param conf
     *          Configuration to be changed. Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeCmpControl(String name, String conf) throws CaMgmtException;

    Set<String> getEnvParamNames();

    /**
     * Gets the value the environment parameter {@code name}.
     * @param name
     *          Environment name. Must not be {@code null}.
     * @return the value the environment parameter.
     */
    String getEnvParam(String name);

    /**
     * Adds a environment parameter.
     * @param name
     *          Environment name. Must not be {@code null}.
     * @param value
     *          Environment value. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addEnvParam(String name, String value) throws CaMgmtException;

    /**
     * Removes the environment parameter {@code envParamName}.
     * @param envParamName
     *          Environment name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeEnvParam(String envParamName) throws CaMgmtException;

    /**
     * Changes the environment parameter {@code name}.
     * @param name
     *          name of the CMP control to be changed. Must not be {@code null}.
     * @param value
     *          Environment value to be changed. Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeEnvParam(String name, String value) throws CaMgmtException;

    /**
     * Revokes the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param revocationInfo
     *          Revocation information. Must not be {@code null}.
     * @return whether the revoke is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean revokeCa(String caName, CertRevocationInfo revocationInfo)
            throws CaMgmtException;

    /**
     * Unrevokes the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return whether the unrevoke is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean unrevokeCa(String caName) throws CaMgmtException;

    /**
     * Revokes a certificate with the serial number {@code serialNumber}, and
     * issued by the CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @param reason
     *          Revocation reason. Must not be {@code null}.
     * @param invalidityTime
     *          Invalidity time. Could be {@code null}.
     * @return whether the revoke is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean revokeCertificate(String caName, BigInteger serialNumber,
            CrlReason reason, Date invalidityTime) throws CaMgmtException;

    /**
     * Unrevokes a certificate with the serial number {@code serialNumber}, and
     * issued by the CA {@code caName}.
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @return whether the unrevoke is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     * Removes a certificate with the serial number {@code serialNumber}, and
     * issued by the CA {@code caName}.
     *
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeCertificate(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     *
     * CA {@code caName} issues a new certificate.
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
     * @return the issued certificate
     * @throws CaMgmtException
     *          if error occurs.
     */
    X509Certificate generateCertificate(String caName, String profileName,
            byte[] encodedCsr, Date notBefore, Date notAfter)
            throws CaMgmtException;

    /**
     * Generates a self-signed CA certificate
     * @param caEntry
     *          CA entry. Must not be {@code null}.
     * @param certprofileName
     *          Profile name of the root CA certificate. Must not be {@code null}.
     * @param encodedCsr
     *          DER-encoded CSR. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Could be {@code null}.
     * @return the generated certificate
     * @throws CaMgmtException
     *          if error occurs.
     */
    X509Certificate generateRootCa(X509CaEntry caEntry, String certprofileName,
            byte[] encodedCsr, BigInteger serialNumber) throws CaMgmtException;

    /**
     * Adds a user.
     * @param userEntry
     *          AddUser entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addUser(AddUserEntry userEntry) throws CaMgmtException;

    /**
     * Change the user.
     * @param userEntry
     *          User change entry. Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeUser(ChangeUserEntry userEntry) throws CaMgmtException;

    /**
     * Remove the name {@code username}.
     * @param username
     *          User name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeUser(String username) throws CaMgmtException;

    /**
     * Returns the user {@code username}.
     * @param username
     *          User name. Must not be {@code null}.
     * @return the user
     * @throws CaMgmtException
     *          if error occurs.
     */
    UserEntry getUser(String username) throws CaMgmtException;

    /**
     * Generates a new CRL for CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the generated CRL.
     * @throws CaMgmtException
     *          if error occurs.
     */
    X509CRL generateCrlOnDemand(String caName) throws CaMgmtException;

    /**
     * Returns the CRL of CA {@code caName} with the CRL number {@code  crlNumber}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param crlNumber
     *          CRL number. Must not be {@code null}.
     * @return the CRL.
     * @throws CaMgmtException
     *          if error occurs.
     */
    X509CRL getCrl(String caName, BigInteger crlNumber) throws CaMgmtException;

    /**
     * Returns the latest CRL of CA {@code caName}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @return the CRL.
     * @throws CaMgmtException
     *          if error occurs.
     */
    X509CRL getCurrentCrl(String caName) throws CaMgmtException;

    /**
     * Add a SCEP.
     * @param scepEntry
     *          SCEP entry. Must not be {@code null}.
     * @return whether the add is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean addScep(ScepEntry scepEntry) throws CaMgmtException;

    /**
     * Retmove the SCEP {@code name}.
     * @param name
     *          SCEP name. Must not be {@code null}.
     * @return whether the remove is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean removeScep(String name) throws CaMgmtException;

    /**
     * Changes the SCEP.
     * @param scepEntry
     *          SCEP change information. Must not be {@code null}.
     * @return whether the change is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean changeScep(ChangeScepEntry scepEntry) throws CaMgmtException;

    Set<String> getScepNames();

    /**
     * Returns the SCEP {@code name}.
     * @param name
     *          SCEP name. Must not be {@code null}.
     * @return the SCEP
     * @throws CaMgmtException
     *          if error occurs.
     */
    ScepEntry getScepEntry(String name) throws CaMgmtException;

    /**
     * Returns certificate with status information for the CA {@code caName}
     * and with serial number {@code serialNumber}.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @return the certificate with status information.
     * @throws CaMgmtException
     *          if error occurs.
     */
    CertWithStatusInfo getCert(String caName, BigInteger serialNumber)
            throws CaMgmtException;

    /**
     * Loads the CA system configuration.
     * @param conf
     *          Configuration of the CA system. Must not be {@code null}.
     * @return whether the load is successful.
     * @throws CaMgmtException
     *          if error occurs.
     */
    boolean loadConf(CaConf conf) throws CaMgmtException;

    /**
     * Exports the CA system configuration
     * @param zipFilename
     *          Where to save the exported ZIP file. Must be {@code null}.
     * @param caNames
     *          List of the names of CAs to be exported. {@code null} to export all CAs.
     * @return whether the export is successful.
     * @throws IOException
     *          If read the ZIP file fails.
     * @throws CaMgmtException
     *          if non-IO error occurs.
     */
    boolean exportConf(String zipFilename, List<String> caNames)
            throws CaMgmtException, IOException;

    /**
     * Returns a sorted list of certificate meta information. 
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
     * @param numEntries
     *          Maximal number of entries in the returned list.
     * @return a sorted list of certificate meta information.
     * @throws CaMgmtException
     *          if error occurs.
     */
    List<CertListInfo> listCertificates(String caName, X500Name subjectPattern,
            Date validFrom, Date validTo, CertListOrderBy orderBy,
            int numEntries) throws CaMgmtException;

    /**
     * Returns the request used to enroll the given certificate.
     * @param caName
     *          CA name. Must not be {@code null}.
     * @param serialNumber
     *          Serial number. Must not be {@code null}.
     * @return the request bytes
     * @throws CaMgmtException
     *          if error occurs.
     */
    byte[] getCertRequest(String caName, BigInteger serialNumber)
            throws CaMgmtException;

}
