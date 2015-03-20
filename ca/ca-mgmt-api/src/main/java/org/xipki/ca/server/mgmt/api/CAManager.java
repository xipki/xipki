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
import java.util.Set;

import org.xipki.ca.api.profile.CertValidity;
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

    boolean publishRootCA(String caName, String certprofile)
    throws CAMgmtException;

    boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException;

    boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws CAMgmtException;

    boolean removeCA(String caName)
    throws CAMgmtException;

    boolean restartCaSystem();

    boolean addCaAlias(String aliasName, String caName)
    throws CAMgmtException;

    boolean removeCaAlias(String aliasName)
    throws CAMgmtException;

    String getAliasName(String caName);
    String getCaName(String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertprofileNames();

    Set<String> getPublisherNames();

    Set<String> getCmpRequestorNames();

    Set<String> getCrlSignerNames();

    Set<String> getCmpControlNames();

    Set<String> getCaNames();

    boolean addCA(X509CAEntry newCaDbEntry)
    throws CAMgmtException;

    X509CAEntry getCA(String caName);

    boolean changeCA(String name, CAStatus status,
            X509Certificate cert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;

    boolean removeCertprofileFromCA(String profileName, String caName)
    throws CAMgmtException;

    boolean addCertprofileToCA(String profileName, String caName)
    throws CAMgmtException;

    boolean removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException;

    boolean addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException;

    Set<String> getCertprofilesForCA(String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName);

    CmpRequestorEntry getCmpRequestor(String name);

    boolean addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException;

    boolean removeCmpRequestor(String requestorName)
    throws CAMgmtException;

    boolean changeCmpRequestor(String name, String cert)
    throws CAMgmtException;

    boolean removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException;

    boolean addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException;

    CertprofileEntry getCertprofile(String profileName);

    boolean removeCertprofile(String profileName)
    throws CAMgmtException;

    boolean changeCertprofile(String name, String type, String conf)
    throws CAMgmtException;

    boolean addCertprofile(CertprofileEntry dbEntry)
    throws CAMgmtException;

    boolean setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException;

    boolean removeCmpResponder()
    throws CAMgmtException;

    boolean changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException;

    CmpResponderEntry getCmpResponder();

    boolean addCrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException;

    boolean removeCrlSigner(String crlSignerName)
    throws CAMgmtException;

    boolean changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            CRLControl crlControl)
    throws CAMgmtException;

    X509CrlSignerEntry getCrlSigner(String name);

    boolean addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException;

    List<PublisherEntry> getPublishersForCA(String caName);

    PublisherEntry getPublisher(String publisherName);

    boolean removePublisher(String publisherName)
    throws CAMgmtException;

    boolean changePublisher(String name, String type, String conf)
    throws CAMgmtException;

    CmpControl getCmpControl(String name);

    boolean addCmpControl(CmpControl dbEntry)
    throws CAMgmtException;

    boolean removeCmpControl(String name)
    throws CAMgmtException;

    boolean changeCmpControl(CmpControl control)
    throws CAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    boolean addEnvParam(String name, String value)
    throws CAMgmtException;

    boolean removeEnvParam(String envParamName)
    throws CAMgmtException;

    boolean changeEnvParam(String name, String value)
    throws CAMgmtException;

    boolean revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException;

    boolean unrevokeCa(String caName)
    throws CAMgmtException;

    boolean revokeCertificate(String caName, BigInteger serialNumber, CRLReason reason, Date invalidityTime)
    throws CAMgmtException;

    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    boolean removeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    X509Certificate generateCertificate(String caName, String profileName, String user, byte[] encodedPkcs10Request)
    throws CAMgmtException;

    X509Certificate generateSelfSignedCA(
            String name, String certprofileName, byte[] p10Req,
            CAStatus status, long nextSerial, int nextCrlNumber,
            List<String> crl_uris, List<String> delta_crl_uris, List<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;
}
