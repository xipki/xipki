/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.ncm.common;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaSystemStatus;
import org.xipki.pki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeCaEntry;
import org.xipki.pki.ca.server.mgmt.api.ChangeScepEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.pki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.pki.ca.server.mgmt.api.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.X509CrlSignerEntry;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface HessianCaManager {

    String getAttribute(
            String attributeKey);

    CaSystemStatus getCaSystemStatus();

    boolean unlockCa();

    boolean publishRootCa(
            String caName,
            String certprofile)
    throws HessianCaMgmtException;

    boolean republishCertificates(
            String caName,
            List<String> publisherNames)
    throws HessianCaMgmtException;

    boolean clearPublishQueue(
            String caName,
            List<String> publisherNames)
    throws HessianCaMgmtException;

    boolean removeCa(String caName)
    throws HessianCaMgmtException;

    boolean restartCaSystem();

    boolean notifyCaChange()
    throws HessianCaMgmtException;

    boolean addCaAlias(
            String aliasName,
            String caName)
    throws HessianCaMgmtException;

    boolean removeCaAlias(
            String aliasName)
    throws HessianCaMgmtException;

    Set<String> getAliasesForCa(
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

    boolean addCa(
            CaEntry newCaDbEntry)
    throws HessianCaMgmtException;

    CaEntry getCa(String caName);

    boolean changeCa(
            ChangeCaEntry changeCaEntry)
    throws HessianCaMgmtException;

    boolean removeCertprofileFromCa(
            String profileName,
            String caName)
    throws HessianCaMgmtException;

    boolean addCertprofileToCa(
            String profileName,
            String profileLocalname,
            String caName)
    throws HessianCaMgmtException;

    boolean removePublisherFromCa(
            String publisherName,
            String caName)
    throws HessianCaMgmtException;

    boolean addPublisherToCa(
            String publisherName,
            String caName)
    throws HessianCaMgmtException;

    Map<String, String> getCertprofilesForCa(
            String caName);

    Set<CaHasRequestorEntry> getCmpRequestorsForCa(
            String caName);

    CmpRequestorEntry getCmpRequestor(
            String name);

    boolean addCmpRequestor(
            CmpRequestorEntry dbEntry)
    throws HessianCaMgmtException;

    boolean removeCmpRequestor(
            String requestorName)
    throws HessianCaMgmtException;

    boolean changeCmpRequestor(
            String name,
            String base64Cert)
    throws HessianCaMgmtException;

    boolean removeCmpRequestorFromCa(
            String requestorName,
            String caName)
    throws HessianCaMgmtException;

    boolean addCmpRequestorToCa(
            CaHasRequestorEntry requestor,
            String caName)
    throws HessianCaMgmtException;

    CertprofileEntry getCertprofile(
            String profileName);

    boolean removeCertprofile(
            String profileName)
    throws HessianCaMgmtException;

    boolean changeCertprofile(
            String name,
            String type,
            String conf)
    throws HessianCaMgmtException;

    boolean addCertprofile(
            CertprofileEntry dbEntry)
    throws HessianCaMgmtException;

    boolean addCmpResponder(
            CmpResponderEntry dbEntry)
    throws HessianCaMgmtException;

    boolean removeCmpResponder(
            String name)
    throws HessianCaMgmtException;

    boolean changeCmpResponder(
            String name,
            String type,
            String conf,
            String base64Cert)
    throws HessianCaMgmtException;

    CmpResponderEntry getCmpResponder(
            String name);

    boolean addCrlSigner(
            X509CrlSignerEntry dbEntry)
    throws HessianCaMgmtException;

    boolean removeCrlSigner(
            String crlSignerName)
    throws HessianCaMgmtException;

    boolean changeCrlSigner(
            X509ChangeCrlSignerEntry dbEntry)
    throws HessianCaMgmtException;

    X509CrlSignerEntry getCrlSigner(
            String name);

    boolean addPublisher(
            PublisherEntry dbEntry)
    throws HessianCaMgmtException;

    List<PublisherEntry> getPublishersForCa(
            String caName);

    PublisherEntry getPublisher(
            String publisherName);

    boolean removePublisher(
            String publisherName)
    throws HessianCaMgmtException;

    boolean changePublisher(
            String name,
            String type,
            String conf)
    throws HessianCaMgmtException;

    CmpControlEntry getCmpControl(
            String name);

    boolean addCmpControl(
            CmpControlEntry dbEntry)
    throws HessianCaMgmtException;

    boolean removeCmpControl(
            String name)
    throws HessianCaMgmtException;

    boolean changeCmpControl(
            String name,
            String conf)
    throws HessianCaMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(
            String name);

    boolean addEnvParam(
            String name,
            String value)
    throws HessianCaMgmtException;

    boolean removeEnvParam(
            String envParamName)
    throws HessianCaMgmtException;

    boolean changeEnvParam(
            String name,
            String value)
    throws HessianCaMgmtException;

    boolean revokeCa(
            String caName,
            CertRevocationInfo revocationInfo)
    throws HessianCaMgmtException;

    boolean unrevokeCa(
            String caName)
    throws HessianCaMgmtException;

    boolean revokeCertificate(
            String caName,
            BigInteger serialNumber,
            CrlReason reason,
            Date invalidityTime)
    throws HessianCaMgmtException;

    boolean unrevokeCertificate(
            String caName,
            BigInteger serialNumber)
    throws HessianCaMgmtException;

    boolean removeCertificate(
            String caName,
            BigInteger serialNumber)
    throws HessianCaMgmtException;

    byte[] generateCertificate(
            String caName,
            String profileName,
            String user,
            byte[] encodedPkcs10Request)
    throws HessianCaMgmtException;

    X509Certificate generateSelfSignedCa(
            X509CaEntry caEntry,
            String certprofileName,
            byte[] p10Req)
    throws HessianCaMgmtException;

    boolean addUser(
            AddUserEntry userEntry)
    throws HessianCaMgmtException;

    boolean changeUser(
            String username,
            String password,
            String cnRegex)
    throws HessianCaMgmtException;

    boolean removeUser(
            final String username)
    throws HessianCaMgmtException;

    UserEntry getUser(
            String username)
    throws HessianCaMgmtException;

    X509CRL generateCrlOnDemand(
            String caName)
    throws HessianCaMgmtException;

    X509CRL getCrl(
            String caName,
            BigInteger crlNumber)
    throws HessianCaMgmtException;

    X509CRL getCurrentCrl(
            String caName)
    throws HessianCaMgmtException;

    boolean addScep(
            ScepEntry scepEntry)
    throws HessianCaMgmtException;

    boolean removeScep(
            String name)
    throws HessianCaMgmtException;

    boolean changeScep(
            ChangeScepEntry scepEntry)
    throws HessianCaMgmtException;

    Set<String> getScepNames();

    ScepEntry getScepEntry(
            String name)
    throws HessianCaMgmtException;

}
