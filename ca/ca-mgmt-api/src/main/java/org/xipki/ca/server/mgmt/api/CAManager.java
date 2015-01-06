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

import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.CASystemStatus;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.CmpControl;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public interface CAManager
{
    public static final String NULL = "NULL";

    CASystemStatus getCASystemStatus();

    boolean unlockCA();

    void publishRootCA(String caName, String certprofile)
    throws CAMgmtException;

    boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException;

    boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws CAMgmtException;

    void removeCA(String caName)
    throws CAMgmtException;

    boolean restartCaSystem();

    void addCaAlias(String aliasName, String caName)
    throws CAMgmtException;

    void removeCaAlias(String aliasName)
    throws CAMgmtException;

    String getAliasName(String caName);
    String getCaName(String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertProfileNames();

    Set<String> getPublisherNames();

    Set<String> getCmpRequestorNames();

    Set<String> getCrlSignerNames();

    Set<String> getCaNames();

    void addCA(X509CAEntry newCaDbEntry)
    throws CAMgmtException;

    X509CAEntry getCA(String caName);

    void changeCA(String name, CAStatus status,
            X509Certificate cert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;

    void removeCertProfileFromCA(String profileName, String caName)
    throws CAMgmtException;

    void addCertProfileToCA(String profileName, String caName)
    throws CAMgmtException;

    void removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException;

    void addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException;

    Set<String> getCertProfilesForCA(String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName);

    CmpRequestorEntry getCmpRequestor(String name);

    void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException;

    void removeCmpRequestor(String requestorName)
    throws CAMgmtException;

    void changeCmpRequestor(String name, String cert)
    throws CAMgmtException;

    void removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException;

    void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException;

    CertProfileEntry getCertProfile(String profileName);

    void removeCertProfile(String profileName)
    throws CAMgmtException;

    void changeCertProfile(String name, String type, String conf)
    throws CAMgmtException;

    void addCertProfile(CertProfileEntry dbEntry)
    throws CAMgmtException;

    void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException;

    void removeCmpResponder()
    throws CAMgmtException;

    void changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException;

    CmpResponderEntry getCmpResponder();

    void addCrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException;

    void removeCrlSigner(String crlSignerName)
    throws CAMgmtException;

    void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            String crlControl)
    throws CAMgmtException;

    X509CrlSignerEntry getCrlSigner(String name);

    void setCrlSignerInCA(String crlSignerName, String caName)
    throws CAMgmtException;

    void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException;

    List<PublisherEntry> getPublishersForCA(String caName);

    PublisherEntry getPublisher(String publisherName);

    void removePublisher(String publisherName)
    throws CAMgmtException;

    void changePublisher(String name, String type, String conf)
    throws CAMgmtException;

    CmpControl getCmpControl();

    void setCmpControl(CmpControl dbEntry)
    throws CAMgmtException;

    void removeCmpControl()
    throws CAMgmtException;

    void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws CAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    void addEnvParam(String name, String value)
    throws CAMgmtException;

    void removeEnvParam(String envParamName)
    throws CAMgmtException;

    void changeEnvParam(String name, String value)
    throws CAMgmtException;

    void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException;

    void unrevokeCa(String caName)
    throws CAMgmtException;

    boolean revokeCertificate(String caName, BigInteger serialNumber, CRLReason reason, Date invalidityTime)
    throws CAMgmtException;

    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    boolean removeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    X509Certificate generateCertificate(String caName, String profileName, String user, byte[] encodedPkcs10Request)
    throws CAMgmtException;

    public X509Certificate generateSelfSignedCA(
            String name, String certprofileName, String subject,
            CAStatus status, long nextSerial,
            List<String> crl_uris, List<String> delta_crl_uris, List<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;
}
