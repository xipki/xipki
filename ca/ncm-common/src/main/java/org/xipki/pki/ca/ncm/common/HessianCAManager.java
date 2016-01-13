/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.pki.ca.ncm.common;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CAEntry;
import org.xipki.pki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CASystemStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCAEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public interface HessianCAManager {

    String getAttribute(
            String attributeKey);

    CASystemStatus getCASystemStatus();

    boolean unlockCA();

    boolean publishRootCA(
            String caName,
            String certprofile)
    throws HessianCAMgmtException;

    boolean republishCertificates(
            String caName,
            List<String> publisherNames)
    throws HessianCAMgmtException;

    boolean clearPublishQueue(
            String caName,
            List<String> publisherNames)
    throws HessianCAMgmtException;

    boolean removeCA(String caName)
    throws HessianCAMgmtException;

    boolean restartCaSystem();

    boolean notifyCAChange()
    throws HessianCAMgmtException;

    boolean addCaAlias(
            String aliasName,
            String caName)
    throws HessianCAMgmtException;

    boolean removeCaAlias(
            String aliasName)
    throws HessianCAMgmtException;

    Set<String> getAliasesForCA(
            String caName);

    String getCaName(
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
            CAEntry newCaDbEntry)
    throws HessianCAMgmtException;

    CAEntry getCA(String caName);

    boolean changeCA(
            ChangeCAEntry changeCAEntry)
    throws HessianCAMgmtException;

    boolean removeCertprofileFromCA(
            String profileName,
            String caName)
    throws HessianCAMgmtException;

    boolean addCertprofileToCA(
            String profileName,
            String profileLocalname,
            String caName)
    throws HessianCAMgmtException;

    boolean removePublisherFromCA(
            String publisherName,
            String caName)
    throws HessianCAMgmtException;

    boolean addPublisherToCA(
            String publisherName,
            String caName)
    throws HessianCAMgmtException;

    Map<String, String> getCertprofilesForCA(
            String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(
            String caName);

    CmpRequestorEntry getCmpRequestor(
            String name);

    boolean addCmpRequestor(
            CmpRequestorEntry dbEntry)
    throws HessianCAMgmtException;

    boolean removeCmpRequestor(
            String requestorName)
    throws HessianCAMgmtException;

    boolean changeCmpRequestor(
            String name,
            String base64Cert)
    throws HessianCAMgmtException;

    boolean removeCmpRequestorFromCA(
            String requestorName,
            String caName)
    throws HessianCAMgmtException;

    boolean addCmpRequestorToCA(
            CAHasRequestorEntry requestor,
            String caName)
    throws HessianCAMgmtException;

    CertprofileEntry getCertprofile(
            String profileName);

    boolean removeCertprofile(
            String profileName)
    throws HessianCAMgmtException;

    boolean changeCertprofile(
            String name,
            String type,
            String conf)
    throws HessianCAMgmtException;

    boolean addCertprofile(
            CertprofileEntry dbEntry)
    throws HessianCAMgmtException;

    boolean addCmpResponder(
            CmpResponderEntry dbEntry)
    throws HessianCAMgmtException;

    boolean removeCmpResponder(
            String name)
    throws HessianCAMgmtException;

    boolean changeCmpResponder(
            String name,
            String type,
            String conf,
            String base64Cert)
    throws HessianCAMgmtException;

    CmpResponderEntry getCmpResponder(
            String name);

    boolean addCrlSigner(
            X509CrlSignerEntry dbEntry)
    throws HessianCAMgmtException;

    boolean removeCrlSigner(
            String crlSignerName)
    throws HessianCAMgmtException;

    boolean changeCrlSigner(
            X509ChangeCrlSignerEntry dbEntry)
    throws HessianCAMgmtException;

    X509CrlSignerEntry getCrlSigner(
            String name);

    boolean addPublisher(
            PublisherEntry dbEntry)
    throws HessianCAMgmtException;

    List<PublisherEntry> getPublishersForCA(
            String caName);

    PublisherEntry getPublisher(
            String publisherName);

    boolean removePublisher(
            String publisherName)
    throws HessianCAMgmtException;

    boolean changePublisher(
            String name,
            String type,
            String conf)
    throws HessianCAMgmtException;

    CmpControlEntry getCmpControl(
            String name);

    boolean addCmpControl(
            CmpControlEntry dbEntry)
    throws HessianCAMgmtException;

    boolean removeCmpControl(
            String name)
    throws HessianCAMgmtException;

    boolean changeCmpControl(
            String name,
            String conf)
    throws HessianCAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(
            String name);

    boolean addEnvParam(
            String name,
            String value)
    throws HessianCAMgmtException;

    boolean removeEnvParam(
            String envParamName)
    throws HessianCAMgmtException;

    boolean changeEnvParam(
            String name,
            String value)
    throws HessianCAMgmtException;

    boolean revokeCa(
            String caName,
            CertRevocationInfo revocationInfo)
    throws HessianCAMgmtException;

    boolean unrevokeCa(
            String caName)
    throws HessianCAMgmtException;

    boolean revokeCertificate(
            String caName,
            BigInteger serialNumber,
            CRLReason reason,
            Date invalidityTime)
    throws HessianCAMgmtException;

    boolean unrevokeCertificate(
            String caName,
            BigInteger serialNumber)
    throws HessianCAMgmtException;

    boolean removeCertificate(
            String caName,
            BigInteger serialNumber)
    throws HessianCAMgmtException;

    byte[] generateCertificate(
            String caName,
            String profileName,
            String user,
            byte[] encodedPkcs10Request)
    throws HessianCAMgmtException;

    X509Certificate generateSelfSignedCA(
            X509CAEntry caEntry,
            String certprofileName,
            byte[] p10Req)
    throws HessianCAMgmtException;

    boolean addUser(
            AddUserEntry userEntry)
    throws HessianCAMgmtException;

    boolean changeUser(
            String username,
            String password,
            String cnRegex)
    throws HessianCAMgmtException;

    boolean removeUser(
            final String username)
    throws HessianCAMgmtException;

    UserEntry getUser(
            String username)
    throws HessianCAMgmtException;

    X509CRL generateCRLonDemand(
            String caName)
    throws HessianCAMgmtException;

    X509CRL getCRL(
            String caName,
            BigInteger crlNumber)
    throws HessianCAMgmtException;

    X509CRL getCurrentCRL(
            String caName)
    throws HessianCAMgmtException;

    boolean addScep(
            ScepEntry scepEntry)
    throws HessianCAMgmtException;

    boolean removeScep(
            String name)
    throws HessianCAMgmtException;

    boolean changeScep(
            ChangeScepEntry scepEntry)
    throws HessianCAMgmtException;

    Set<String> getScepNames();

    ScepEntry getScepEntry(
            String name)
    throws HessianCAMgmtException;

}
