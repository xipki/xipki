/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.CertRevocationInfo;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface CaManager {

    String NULL = "NULL";

    CaSystemStatus getCASystemStatus();

    boolean unlockCA();

    boolean notifyCAChange()
    throws CaMgmtException;

    boolean publishRootCA(
            String caName,
            String certprofile)
    throws CaMgmtException;

    boolean republishCertificates(
            String caName,
            List<String> publisherNames)
    throws CaMgmtException;

    boolean clearPublishQueue(
            String caName,
            List<String> publisherNames)
    throws CaMgmtException;

    boolean removeCA(
            String caName)
    throws CaMgmtException;

    boolean restartCaSystem();

    boolean addCaAlias(
            String aliasName,
            String caName)
    throws CaMgmtException;

    boolean removeCaAlias(
            String aliasName)
    throws CaMgmtException;

    Set<String> getAliasesForCA(
            String caName);

    String getCaNameForAlias(
            String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertprofileNames();

    Set<String> getPublisherNames();

    Set<String> getCmpRequestorNames();

    Set<String> getCmpResponderNames();

    Set<String> getCrlSignerNames();

    Set<String> getCmpControlNames();

    Set<String> getCaNames();

    boolean addCA(
            CaEntry cEntry)
    throws CaMgmtException;

    CaEntry getCA(
            String caName);

    boolean changeCA(
            ChangeCaEntry changeCAentry)
    throws CaMgmtException;

    boolean removeCertprofileFromCA(
            String profileLocalname,
            String caName)
    throws CaMgmtException;

    boolean addCertprofileToCA(
            String profileName,
            String profileLocalname,
            String caName)
    throws CaMgmtException;

    boolean removePublisherFromCA(
            String publisherName,
            String caName)
    throws CaMgmtException;

    boolean addPublisherToCA(
            String publisherName,
            String caName)
    throws CaMgmtException;

    Map<String, String> getCertprofilesForCA(
            String caName);

    Set<CaHasRequestorEntry> getCmpRequestorsForCA(
            String caName);

    CmpRequestorEntry getCmpRequestor(
            String name);

    boolean addCmpRequestor(
            CmpRequestorEntry dbEntry)
    throws CaMgmtException;

    boolean removeCmpRequestor(
            String requestorName)
    throws CaMgmtException;

    boolean changeCmpRequestor(
            String name,
            String base64Cert)
    throws CaMgmtException;

    boolean removeCmpRequestorFromCA(
            String requestorName,
            String caName)
    throws CaMgmtException;

    boolean addCmpRequestorToCA(
            CaHasRequestorEntry requestor,
            String caName)
    throws CaMgmtException;

    CertprofileEntry getCertprofile(
            String profileName);

    boolean removeCertprofile(
            String profileName)
    throws CaMgmtException;

    boolean changeCertprofile(
            String name,
            String type,
            String conf)
    throws CaMgmtException;

    boolean addCertprofile(
            CertprofileEntry dbEntry)
    throws CaMgmtException;

    boolean addCmpResponder(
            CmpResponderEntry dbEntry)
    throws CaMgmtException;

    boolean removeCmpResponder(
            String name)
    throws CaMgmtException;

    CmpResponderEntry getCmpResponder(
            String name);

    boolean changeCmpResponder(
            String name,
            String type,
            String conf,
            String base64Cert)
    throws CaMgmtException;

    boolean addCrlSigner(
            X509CrlSignerEntry dbEntry)
    throws CaMgmtException;

    boolean removeCrlSigner(
            String crlSignerName)
    throws CaMgmtException;

    boolean changeCrlSigner(
            X509ChangeCrlSignerEntry dbEntry)
    throws CaMgmtException;

    X509CrlSignerEntry getCrlSigner(
            String name);

    boolean addPublisher(
            PublisherEntry dbEntry)
    throws CaMgmtException;

    List<PublisherEntry> getPublishersForCA(
            String caName);

    PublisherEntry getPublisher(
            String publisherName);

    boolean removePublisher(
            String publisherName)
    throws CaMgmtException;

    boolean changePublisher(
            String name,
            String type,
            String conf)
    throws CaMgmtException;

    CmpControlEntry getCmpControl(
            String name);

    boolean addCmpControl(
            CmpControlEntry dbEntry)
    throws CaMgmtException;

    boolean removeCmpControl(
            String name)
    throws CaMgmtException;

    boolean changeCmpControl(
            String name,
            String conf)
    throws CaMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    boolean addEnvParam(
            String name,
            String value)
    throws CaMgmtException;

    boolean removeEnvParam(
            String envParamName)
    throws CaMgmtException;

    boolean changeEnvParam(
            String name,
            String value)
    throws CaMgmtException;

    boolean revokeCa(
            String caName,
            CertRevocationInfo revocationInfo)
    throws CaMgmtException;

    boolean unrevokeCa(
            String caName)
    throws CaMgmtException;

    boolean revokeCertificate(
            String caName,
            BigInteger serialNumber,
            CrlReason reason,
            Date invalidityTime)
    throws CaMgmtException;

    boolean unrevokeCertificate(
            String caName,
            BigInteger serialNumber)
    throws CaMgmtException;

    boolean removeCertificate(
            String caName,
            BigInteger serialNumber)
    throws CaMgmtException;

    X509Certificate generateCertificate(
            String caName,
            String profileName,
            String user,
            byte[] encodedPkcs10Request)
    throws CaMgmtException;

    X509Certificate generateRootCA(
            X509CaEntry caEntry,
            String certprofileName,
            byte[] p10Req)
    throws CaMgmtException;

    boolean addUser(
            AddUserEntry userEntry)
    throws CaMgmtException;

    boolean changeUser(
            String username,
            String password,
            String cnRegex)
    throws CaMgmtException;

    boolean removeUser(
            String username)
    throws CaMgmtException;

    UserEntry getUser(
            String username)
    throws CaMgmtException;

    X509CRL generateCRLonDemand(
            String caName)
    throws CaMgmtException;

    X509CRL getCRL(
            String caName,
            BigInteger crlNumber)
    throws CaMgmtException;

    X509CRL getCurrentCRL(
            String caName)
    throws CaMgmtException;

    boolean addScep(
            ScepEntry scepEntry)
    throws CaMgmtException;

    boolean removeScep(
            String name)
    throws CaMgmtException;

    boolean changeScep(
            ChangeScepEntry scepEntry)
    throws CaMgmtException;

    Set<String> getScepNames();

    ScepEntry getScepEntry(
            String name)
    throws CaMgmtException;

}
