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
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.xipki.commons.security.CertRevocationInfo;
import org.xipki.commons.security.CrlReason;
import org.xipki.pki.ca.server.mgmt.api.conf.CaConf;
import org.xipki.pki.ca.server.mgmt.api.x509.CertWithStatusInfo;
import org.xipki.pki.ca.server.mgmt.api.x509.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaManager {

    String NULL = "NULL";

    CaSystemStatus getCaSystemStatus();

    boolean unlockCa();

    boolean notifyCaChange() throws CaMgmtException;

    boolean republishCertificates(@Nullable String caName, @Nullable List<String> publisherNames,
            int numThreads) throws CaMgmtException;

    boolean clearPublishQueue(@Nullable String caName, @Nullable List<String> publisherNames)
            throws CaMgmtException;

    boolean removeCa(@NonNull String caName) throws CaMgmtException;

    boolean restartCaSystem();

    boolean addCaAlias(@NonNull String aliasName, @NonNull String caName) throws CaMgmtException;

    boolean removeCaAlias(@NonNull String aliasName) throws CaMgmtException;

    Set<String> getAliasesForCa(@NonNull String caName);

    String getCaNameForAlias(@NonNull String aliasName);

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

    boolean addCa(@NonNull CaEntry caEntry) throws CaMgmtException;

    CaEntry getCa(@NonNull String caName);

    boolean changeCa(@NonNull ChangeCaEntry changeCAentry) throws CaMgmtException;

    boolean removeCertprofileFromCa(@NonNull String profileName, @NonNull String caName)
            throws CaMgmtException;

    boolean addCertprofileToCa(@NonNull String profileName, @NonNull String caName)
            throws CaMgmtException;

    boolean removePublisherFromCa(@NonNull String publisherName, @NonNull String caName)
            throws CaMgmtException;

    boolean addPublisherToCa(@NonNull String publisherName, @NonNull String caName)
            throws CaMgmtException;

    Set<String> getCertprofilesForCa(@NonNull String caName);

    Set<CaHasRequestorEntry> getRequestorsForCa(@NonNull String caName);

    CmpRequestorEntry getRequestor(@NonNull String name);

    boolean addRequestor(@NonNull CmpRequestorEntry dbEntry) throws CaMgmtException;

    boolean removeRequestor(@NonNull String requestorName) throws CaMgmtException;

    boolean changeRequestor(@NonNull String name, @NonNull String base64Cert)
            throws CaMgmtException;

    boolean removeRequestorFromCa(@NonNull String requestorName, @NonNull String caName)
            throws CaMgmtException;

    boolean addRequestorToCa(@NonNull CaHasRequestorEntry requestor, @NonNull String caName)
            throws CaMgmtException;

    boolean removeUserFromCa(@NonNull String userName, @NonNull String caName)
            throws CaMgmtException;

    boolean addUserToCa(@NonNull CaHasUserEntry user, @NonNull String caName)
            throws CaMgmtException;

    /**
     * Returns map between CA name an CaHasUserEntry for given user.
     * @param user User
     * @return map between CA name and CaHasUserEntry for given user.
     * @throws CaMgmtException If error occurs.
     */
    Map<String, CaHasUserEntry> getCaHasUsers(String user)
            throws CaMgmtException;

    CertprofileEntry getCertprofile(@NonNull String profileName);

    boolean removeCertprofile(@NonNull String profileName) throws CaMgmtException;

    boolean changeCertprofile(@NonNull String name, @Nullable String type, @Nullable String conf)
            throws CaMgmtException;

    boolean addCertprofile(@NonNull CertprofileEntry dbEntry) throws CaMgmtException;

    boolean addResponder(@NonNull CmpResponderEntry dbEntry) throws CaMgmtException;

    boolean removeResponder(@NonNull String name) throws CaMgmtException;

    CmpResponderEntry getResponder(@NonNull String name);

    boolean changeResponder(@NonNull String name, @Nullable String type, @Nullable String conf,
            @Nullable String base64Cert) throws CaMgmtException;

    boolean addCrlSigner(@NonNull X509CrlSignerEntry dbEntry) throws CaMgmtException;

    boolean removeCrlSigner(@NonNull String crlSignerName) throws CaMgmtException;

    boolean changeCrlSigner(@NonNull X509ChangeCrlSignerEntry dbEntry) throws CaMgmtException;

    X509CrlSignerEntry getCrlSigner(@NonNull String name);

    boolean addPublisher(@NonNull PublisherEntry dbEntry) throws CaMgmtException;

    List<PublisherEntry> getPublishersForCa(@NonNull String caName);

    PublisherEntry getPublisher(@NonNull String publisherName);

    boolean removePublisher(@NonNull String publisherName) throws CaMgmtException;

    boolean changePublisher(@NonNull String name, @Nullable String type, @Nullable String conf)
            throws CaMgmtException;

    CmpControlEntry getCmpControl(@NonNull String name);

    boolean addCmpControl(@NonNull CmpControlEntry dbEntry) throws CaMgmtException;

    boolean removeCmpControl(@NonNull String name) throws CaMgmtException;

    boolean changeCmpControl(@NonNull String name, @Nullable String conf) throws CaMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(@NonNull String name);

    boolean addEnvParam(@NonNull String name, @NonNull String value) throws CaMgmtException;

    boolean removeEnvParam(@NonNull String envParamName) throws CaMgmtException;

    boolean changeEnvParam(@NonNull String name, @NonNull String value) throws CaMgmtException;

    boolean revokeCa(@NonNull String caName, @NonNull CertRevocationInfo revocationInfo)
            throws CaMgmtException;

    boolean unrevokeCa(@NonNull String caName) throws CaMgmtException;

    boolean revokeCertificate(@NonNull String caName, @NonNull BigInteger serialNumber,
            @NonNull CrlReason reason, @Nullable Date invalidityTime) throws CaMgmtException;

    boolean unrevokeCertificate(@NonNull String caName, @NonNull BigInteger serialNumber)
            throws CaMgmtException;

    boolean removeCertificate(@NonNull String caName, @NonNull BigInteger serialNumber)
            throws CaMgmtException;

    X509Certificate generateCertificate(@NonNull String caName, @NonNull String profileName,
            @NonNull byte[] encodedCsr, @Nullable Date notBefore, @Nullable Date notAfter)
            throws CaMgmtException;

    X509Certificate generateRootCa(@NonNull X509CaEntry caEntry, @NonNull String certprofileName,
            @NonNull byte[] encodedCsr, @Nullable BigInteger serialNumber) throws CaMgmtException;

    boolean addUser(@NonNull AddUserEntry userEntry) throws CaMgmtException;

    boolean changeUser(@NonNull ChangeUserEntry userEntry) throws CaMgmtException;

    boolean removeUser(@NonNull String username) throws CaMgmtException;

    UserEntry getUser(@NonNull String username) throws CaMgmtException;

    X509CRL generateCrlOnDemand(@NonNull String caName) throws CaMgmtException;

    X509CRL getCrl(@NonNull String caName, @NonNull BigInteger crlNumber) throws CaMgmtException;

    X509CRL getCurrentCrl(@NonNull String caName) throws CaMgmtException;

    boolean addScep(@NonNull ScepEntry scepEntry) throws CaMgmtException;

    boolean removeScep(@NonNull String name) throws CaMgmtException;

    boolean changeScep(@NonNull ChangeScepEntry scepEntry) throws CaMgmtException;

    Set<String> getScepNames();

    ScepEntry getScepEntry(@NonNull String name) throws CaMgmtException;

    CertWithStatusInfo getCert(@NonNull String caName, @NonNull BigInteger serialNumber)
            throws CaMgmtException;

    /**
     * @since 2.1.0
     */
    boolean loadConf(@NonNull CaConf conf) throws CaMgmtException;

    /**
     * @since 2.1.0
     */
    boolean exportConf(@NonNull String zipFilename, @Nullable List<String> caNames)
            throws CaMgmtException, IOException;

    /**
     * @since 2.1.0
     */
    List<CertListInfo> listCertificates(@NonNull String caName, @Nullable X500Name subjectPattern,
            @Nullable Date validFrom, @Nullable Date validTo, @Nullable CertListOrderBy orderBy,
            int numEntries) throws CaMgmtException;

    /**
     * @since 2.1.0
     */
    byte[] getCertRequest(@NonNull String caName, @NonNull BigInteger serialNumber)
            throws CaMgmtException;

}
