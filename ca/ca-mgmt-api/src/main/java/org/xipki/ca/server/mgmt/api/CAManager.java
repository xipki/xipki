/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ca.server.mgmt.api;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public interface CAManager
{
    static final String NULL = "NULL";

    CASystemStatus getCASystemStatus();

    boolean unlockCA();

    boolean notifyCAChange()
    throws CAMgmtException;

    boolean publishRootCA(
            String caName,
            String certprofile)
    throws CAMgmtException;

    boolean republishCertificates(
            String caName,
            List<String> publisherNames)
    throws CAMgmtException;

    boolean clearPublishQueue(
            String caName,
            List<String> publisherNames)
    throws CAMgmtException;

    boolean removeCA(
            String caName)
    throws CAMgmtException;

    boolean restartCaSystem();

    boolean addCaAlias(
            String aliasName,
            String caName)
    throws CAMgmtException;

    boolean removeCaAlias(
            String aliasName)
    throws CAMgmtException;

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
            CAEntry cEntry)
    throws CAMgmtException;

    CAEntry getCA(
            String caName);

    boolean changeCA(
            ChangeCAEntry changeCAentry)
    throws CAMgmtException;

    boolean removeCertprofileFromCA(
            String profileLocalname,
            String caName)
    throws CAMgmtException;

    boolean addCertprofileToCA(
            String profileName,
            String profileLocalname,
            String caName)
    throws CAMgmtException;

    boolean removePublisherFromCA(
            String publisherName,
            String caName)
    throws CAMgmtException;

    boolean addPublisherToCA(
            String publisherName,
            String caName)
    throws CAMgmtException;

    Map<String, String> getCertprofilesForCA(
            String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(
            String caName);

    CmpRequestorEntry getCmpRequestor(
            String name);

    boolean addCmpRequestor(
            CmpRequestorEntry dbEntry)
    throws CAMgmtException;

    boolean removeCmpRequestor(
            String requestorName)
    throws CAMgmtException;

    boolean changeCmpRequestor(
            String name,
            String base64Cert)
    throws CAMgmtException;

    boolean removeCmpRequestorFromCA(
            String requestorName,
            String caName)
    throws CAMgmtException;

    boolean addCmpRequestorToCA(
            CAHasRequestorEntry requestor,
            String caName)
    throws CAMgmtException;

    CertprofileEntry getCertprofile(
            String profileName);

    boolean removeCertprofile(
            String profileName)
    throws CAMgmtException;

    boolean changeCertprofile(
            String name,
            String type,
            String conf)
    throws CAMgmtException;

    boolean addCertprofile(
            CertprofileEntry dbEntry)
    throws CAMgmtException;

    boolean addCmpResponder(
            CmpResponderEntry dbEntry)
    throws CAMgmtException;

    boolean removeCmpResponder(
            String name)
    throws CAMgmtException;

    CmpResponderEntry getCmpResponder(
            String name);

    boolean changeCmpResponder(
            String name,
            String type,
            String conf,
            String base64Cert)
    throws CAMgmtException;

    boolean addCrlSigner(
            X509CrlSignerEntry dbEntry)
    throws CAMgmtException;

    boolean removeCrlSigner(
            String crlSignerName)
    throws CAMgmtException;

    boolean changeCrlSigner(
            X509ChangeCrlSignerEntry dbEntry)
    throws CAMgmtException;

    X509CrlSignerEntry getCrlSigner(
            String name);

    boolean addPublisher(
            PublisherEntry dbEntry)
    throws CAMgmtException;

    List<PublisherEntry> getPublishersForCA(
            String caName);

    PublisherEntry getPublisher(
            String publisherName);

    boolean removePublisher(
            String publisherName)
    throws CAMgmtException;

    boolean changePublisher(
            String name,
            String type,
            String conf)
    throws CAMgmtException;

    CmpControlEntry getCmpControl(
            String name);

    boolean addCmpControl(
            CmpControlEntry dbEntry)
    throws CAMgmtException;

    boolean removeCmpControl(
            String name)
    throws CAMgmtException;

    boolean changeCmpControl(
            String name,
            String conf)
    throws CAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    boolean addEnvParam(
            String name,
            String value)
    throws CAMgmtException;

    boolean removeEnvParam(
            String envParamName)
    throws CAMgmtException;

    boolean changeEnvParam(
            String name,
            String value)
    throws CAMgmtException;

    boolean revokeCa(
            String caName,
            CertRevocationInfo revocationInfo)
    throws CAMgmtException;

    boolean unrevokeCa(
            String caName)
    throws CAMgmtException;

    boolean revokeCertificate(
            String caName,
            BigInteger serialNumber,
            CRLReason reason,
            Date invalidityTime)
    throws CAMgmtException;

    boolean unrevokeCertificate(
            String caName,
            BigInteger serialNumber)
    throws CAMgmtException;

    boolean removeCertificate(
            String caName,
            BigInteger serialNumber)
    throws CAMgmtException;

    X509Certificate generateCertificate(
            String caName,
            String profileName,
            String user,
            byte[] encodedPkcs10Request)
    throws CAMgmtException;

    X509Certificate generateRootCA(
            X509CAEntry caEntry,
            String certprofileName,
            byte[] p10Req)
    throws CAMgmtException;
}
