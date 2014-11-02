/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.mgmt.hessian.common;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.CertValidity;
import org.xipki.ca.common.CmpControl;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.CrlSignerEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public interface HessianCAManager
{
    String getAttribute(String attributeKey);

    CASystemStatus getCASystemStatus();

    boolean unlockCA();

    void publishRootCA(String caName, String certprofile)
    throws HessianCAMgmtException;

    boolean republishCertificates(String caName, List<String> publisherNames)
    throws HessianCAMgmtException;

    boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws HessianCAMgmtException;

    void removeCA(String caName)
    throws HessianCAMgmtException;

    boolean restartCaSystem();

    void addCaAlias(String aliasName, String caName)
    throws HessianCAMgmtException;

    void removeCaAlias(String aliasName)
    throws HessianCAMgmtException;

    String getAliasName(String caName);
    String getCaName(String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertProfileNames();

    Set<String> getPublisherNames();

    Set<String> getCmpRequestorNames();

    Set<String> getCrlSignerNames();

    Set<String> getCaNames();

    void addCA(CAEntry newCaDbEntry)
    throws HessianCAMgmtException;

    CAEntry getCA(String caName);

    void changeCA(String name, CAStatus status,
            byte[] encodedCert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws HessianCAMgmtException;

    void removeCertProfileFromCA(String profileName, String caName)
    throws HessianCAMgmtException;

    void addCertProfileToCA(String profileName, String caName)
    throws HessianCAMgmtException;

    void removePublisherFromCA(String publisherName, String caName)
    throws HessianCAMgmtException;

    void addPublisherToCA(String publisherName, String caName)
    throws HessianCAMgmtException;

    Set<String> getCertProfilesForCA(String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName);

    CmpRequestorEntry getCmpRequestor(String name);

    void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws HessianCAMgmtException;

    void removeCmpRequestor(String requestorName)
    throws HessianCAMgmtException;

    void changeCmpRequestor(String name, String cert)
    throws HessianCAMgmtException;

    void removeCmpRequestorFromCA(String requestorName, String caName)
    throws HessianCAMgmtException;

    void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws HessianCAMgmtException;

    CertProfileEntry getCertProfile(String profileName);

    void removeCertProfile(String profileName)
    throws HessianCAMgmtException;

    void changeCertProfile(String name, String type, String conf)
    throws HessianCAMgmtException;

    void addCertProfile(CertProfileEntry dbEntry)
    throws HessianCAMgmtException;

    void setCmpResponder(CmpResponderEntry dbEntry)
    throws HessianCAMgmtException;

    void removeCmpResponder()
    throws HessianCAMgmtException;

    void changeCmpResponder(String type, String conf, String cert)
    throws HessianCAMgmtException;

    CmpResponderEntry getCmpResponder();

    void addCrlSigner(CrlSignerEntry dbEntry)
    throws HessianCAMgmtException;

    void removeCrlSigner(String crlSignerName)
    throws HessianCAMgmtException;

    void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            String crlControl)
    throws HessianCAMgmtException;

    CrlSignerEntry getCrlSigner(String name);

    void setCrlSignerInCA(String crlSignerName, String caName)
    throws HessianCAMgmtException;

    void addPublisher(PublisherEntry dbEntry)
    throws HessianCAMgmtException;

    List<PublisherEntry> getPublishersForCA(String caName);

    PublisherEntry getPublisher(String publisherName);

    void removePublisher(String publisherName)
    throws HessianCAMgmtException;

    void changePublisher(String name, String type, String conf)
    throws HessianCAMgmtException;

    CmpControl getCmpControl();

    void setCmpControl(CmpControl dbEntry)
    throws HessianCAMgmtException;

    void removeCmpControl()
    throws HessianCAMgmtException;

    void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws HessianCAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    void addEnvParam(String name, String value)
    throws HessianCAMgmtException;

    void removeEnvParam(String envParamName)
    throws HessianCAMgmtException;

    void changeEnvParam(String name, String value)
    throws HessianCAMgmtException;

    void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws HessianCAMgmtException;

    void unrevokeCa(String caName)
    throws HessianCAMgmtException;

    boolean revokeCertificate(String caName, BigInteger serialNumber, CRLReason reason, Date invalidityTime)
    throws HessianCAMgmtException;

    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws HessianCAMgmtException;

    boolean removeCertificate(String caName, BigInteger serialNumber)
    throws HessianCAMgmtException;

    byte[] generateCertificate(String caName, String profileName, String user, byte[] encodedPkcs10Request)
    throws HessianCAMgmtException;

    public X509Certificate generateSelfSignedCA(
            String name, String certprofileName, String subject,
            CAStatus status, long nextSerial,
            List<String> crl_uris, List<String> delta_crl_uris, List<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws HessianCAMgmtException;
}
