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

package org.xipki.ca.mgmt.hessian.client.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.mgmt.hessian.common.HessianCAManager;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CAMgmtException;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.CASystemStatus;
import org.xipki.ca.server.mgmt.api.CRLControl;
import org.xipki.ca.server.mgmt.api.CertprofileEntry;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.api.X509CrlSignerEntry;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.SecurityUtil;

import com.caucho.hessian.client.HessianProxyFactory;

/**
 * @author Lijun Liao
 */

public class CAManagerClient implements CAManager
{

    private final Logger LOG = LoggerFactory.getLogger(getClass());
    private HessianCAManager client;
    private int version;

    private String serverURL;

    public CAManagerClient()
    {
    }

    public void init()
    throws Exception
    {
        if(serverURL == null)
        {
            throw new IllegalStateException("serverURL is not set");
        }
        HessianProxyFactory factory = new HessianProxyFactory(getClass().getClassLoader());
        factory.setHessian2Request(true);
        factory.setHessian2Reply(true);

        this.client = (HessianCAManager) factory.create(
                HessianCAManager.class, serverURL);
        determineServerVersion();
    }

    public void shutdown()
    throws Exception
    {
    }

    public void setServerURL(String serverURL)
    {
        this.serverURL = serverURL;
    }

    private void determineServerVersion()
    {
        String versionS = client.getAttribute("version");
        if(versionS == null)
        {
            version = 0;
        }
        else
        {
            try
            {
                version = Integer.parseInt(versionS);
            }catch(NumberFormatException e)
            {
                LOG.info("invalid version {}, reset it to 0", versionS);
            }
        }
        LOG.info("set version to {}", version);
    }

    @Override
    public CASystemStatus getCASystemStatus()
    {
        return client.getCASystemStatus();
    }

    @Override
    public boolean unlockCA()
    {
        return client.unlockCA();
    }

    @Override
    public void publishRootCA(String caName, String certprofile)
    throws CAMgmtException
    {
        client.publishRootCA(caName, certprofile);
    }

    @Override
    public boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException
    {
        return client.republishCertificates(caName, publisherNames);
    }

    @Override
    public boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws CAMgmtException
    {
        return client.clearPublishQueue(caName, publisherNames);
    }

    @Override
    public void removeCA(String caName)
    throws CAMgmtException
    {
        client.removeCA(caName);
    }

    @Override
    public boolean restartCaSystem()
    {
        return client.restartCaSystem();
    }

    @Override
    public void notifyCAChange()
    {
        client.notifyCAChange();
    }

    @Override
    public void addCaAlias(String aliasName, String caName)
    throws CAMgmtException
    {
        client.addCaAlias(aliasName, caName);
    }

    @Override
    public void removeCaAlias(String aliasName)
    throws CAMgmtException
    {
        client.removeCaAlias(aliasName);
    }

    @Override
    public String getAliasName(String caName)
    {
        return client.getAliasName(caName);
    }

    @Override
    public String getCaName(String aliasName)
    {
        return client.getCaName(aliasName);
    }

    @Override
    public Set<String> getCaAliasNames()
    {
        return client.getCaAliasNames();
    }

    @Override
    public Set<String> getCertprofileNames()
    {
        return client.getCertprofileNames();
    }

    @Override
    public Set<String> getPublisherNames()
    {
        return client.getPublisherNames();
    }

    @Override
    public Set<String> getCmpRequestorNames()
    {
        return client.getCmpRequestorNames();
    }

    @Override
    public Set<String> getCrlSignerNames()
    {
        return client.getCrlSignerNames();
    }

    @Override
    public Set<String> getCmpControlNames()
    {
        return client.getCmpControlNames();
    }

    @Override
    public Set<String> getCaNames()
    {
        return client.getCaNames();
    }

    @Override
    public void addCA(X509CAEntry newCaDbEntry)
    throws CAMgmtException
    {
        client.addCA(newCaDbEntry);
    }

    @Override
    public X509CAEntry getCA(String caName)
    {
        return client.getCA(caName);
    }

    @Override
    public void changeCA(String name, CAStatus status,
            X509Certificate cert, Set<String> crl_uris,
            Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        client.changeCA(name, status, cert, crl_uris, delta_crl_uris, ocsp_uris,
                max_validity, signer_type, signer_conf, crlsigner_name, cmpcontrol_name,
                duplicate_key, duplicate_subject,
                permissions, numCrls, expirationPeriod, validityMode);
    }

    @Override
    public void removeCertprofileFromCA(String profileName, String caName)
    throws CAMgmtException
    {
        client.removeCertprofileFromCA(profileName, caName);
    }

    @Override
    public void addCertprofileToCA(String profileName, String caName)
    throws CAMgmtException
    {
        client.addCertprofileToCA(profileName, caName);
    }

    @Override
    public void removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException
    {
        client.removePublisherFromCA(publisherName, caName);
    }

    @Override
    public void addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException
    {
        client.addPublisherToCA(publisherName, caName);
    }

    @Override
    public Set<String> getCertprofilesForCA(String caName)
    {
        return client.getCertprofilesForCA(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName)
    {
        return client.getCmpRequestorsForCA(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(String name)
    {
        return client.getCmpRequestor(name);
    }

    @Override
    public void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException
    {
        client.addCmpRequestor(dbEntry);
    }

    @Override
    public void removeCmpRequestor(String requestorName)
    throws CAMgmtException
    {
        client.removeCmpRequestor(requestorName);
    }

    @Override
    public void changeCmpRequestor(String name, String cert)
    throws CAMgmtException
    {
        client.changeCmpRequestor(name, cert);
    }

    @Override
    public void removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException
    {
        client.removeCmpRequestorFromCA(requestorName, caName);
    }

    @Override
    public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException
    {
        client.addCmpRequestorToCA(requestor, caName);
    }

    @Override
    public CertprofileEntry getCertprofile(String profileName)
    {
        return client.getCertprofile(profileName);
    }

    @Override
    public void removeCertprofile(String profileName)
    throws CAMgmtException
    {
        client.removeCertprofile(profileName);
    }

    @Override
    public void changeCertprofile(String name, String type, String conf)
    throws CAMgmtException
    {
        client.changeCertprofile(name, type, conf);
    }

    @Override
    public void addCertprofile(CertprofileEntry dbEntry)
    throws CAMgmtException
    {
        client.addCertprofile(dbEntry);
    }

    @Override
    public void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException
    {
        client.setCmpResponder(dbEntry);
    }

    @Override
    public void removeCmpResponder()
    throws CAMgmtException
    {
        client.removeCmpResponder();
    }

    @Override
    public void changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException
    {
        client.changeCmpResponder(type, conf, cert);
    }

    @Override
    public CmpResponderEntry getCmpResponder()
    {
        return client.getCmpResponder();
    }

    @Override
    public void addCrlSigner(X509CrlSignerEntry dbEntry)
    throws CAMgmtException
    {
        client.addCrlSigner(dbEntry);
    }

    @Override
    public void removeCrlSigner(String crlSignerName)
    throws CAMgmtException
    {
        client.removeCrlSigner(crlSignerName);
    }

    @Override
    public void changeCrlSigner(String name, String signer_type,
            String signer_conf, String signer_cert, CRLControl crlControl)
    throws CAMgmtException
    {
        client.changeCrlSigner(name, signer_type, signer_conf, signer_cert, crlControl);
    }

    @Override
    public X509CrlSignerEntry getCrlSigner(String name)
    {
        return client.getCrlSigner(name);
    }

    @Override
    public void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException
    {
        client.addPublisher(dbEntry);
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(String caName)
    {
        return client.getPublishersForCA(caName);
    }

    @Override
    public PublisherEntry getPublisher(String publisherName)
    {
        return client.getPublisher(publisherName);
    }

    @Override
    public void removePublisher(String publisherName)
    throws CAMgmtException
    {
        client.removePublisher(publisherName);
    }

    @Override
    public void changePublisher(String name, String type, String conf)
    throws CAMgmtException
    {
        client.changePublisher(name, type, conf);
    }

    @Override
    public CmpControl getCmpControl(String name)
    {
        return client.getCmpControl(name);
    }

    @Override
    public void addCmpControl(CmpControl dbEntry)
    throws CAMgmtException
    {
        client.addCmpControl(dbEntry);
    }

    @Override
    public void removeCmpControl(String name)
    throws CAMgmtException
    {
        client.removeCmpControl(name);
    }

    @Override
    public void changeCmpControl(String name, Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert,
            Boolean sendResponderCert)
    throws CAMgmtException
    {
        client.changeCmpControl(name, requireConfirmCert, requireMessageTime, messageTimeBias,
                confirmWaitTime, sendCaCert, sendResponderCert);
    }

    @Override
    public Set<String> getEnvParamNames()
    {
        return client.getEnvParamNames();
    }

    @Override
    public String getEnvParam(String name)
    {
        return client.getEnvParam(name);
    }

    @Override
    public void addEnvParam(String name, String value)
    throws CAMgmtException
    {
        client.addEnvParam(name, value);
    }

    @Override
    public void removeEnvParam(String envParamName)
    throws CAMgmtException
    {
        client.removeEnvParam(envParamName);
    }

    @Override
    public void changeEnvParam(String name, String value)
    throws CAMgmtException
    {
        client.changeEnvParam(name, value);
    }

    @Override
    public void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException
    {
        client.revokeCa(caName, revocationInfo);
    }

    @Override
    public void unrevokeCa(String caName)
    throws CAMgmtException
    {
        client.unrevokeCa(caName);
    }

    @Override
    public boolean revokeCertificate(String caName, BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws CAMgmtException
    {
        return client.revokeCertificate(caName, serialNumber, reason, invalidityTime);
    }

    @Override
    public boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException
    {
        return client.unrevokeCertificate(caName, serialNumber);
    }

    @Override
    public boolean removeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException
    {
        return client.removeCertificate(caName, serialNumber);
    }

    @Override
    public X509Certificate generateCertificate(String caName,
            String profileName, String user, byte[] encodedPkcs10Request)
    throws CAMgmtException
    {
        byte[] encodedCert = client.generateCertificate(caName, profileName, user, encodedPkcs10Request);
        try
        {
            return SecurityUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new CAMgmtException("Could not parse the certificate: " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate generateSelfSignedCA(String name,
            String certprofileName, byte[] p10Req, CAStatus status,
            long nextSerial, int nextCrlNo, List<String> crl_uris,
            List<String> delta_crl_uris, List<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        return client.generateSelfSignedCA(name, certprofileName, p10Req, status,
                nextSerial, nextCrlNo, crl_uris, delta_crl_uris, ocsp_uris, max_validity,
                signer_type, signer_conf, crlsigner_name, cmpcontrol_name,
                duplicate_key, duplicate_subject,
                permissions, numCrls, expirationPeriod, validityMode);
    }

    public static void main(String[] args)
    {
        try
        {
            CAManagerClient c = new CAManagerClient();
            c.setServerURL("http://localhost:8080/pkiconsole/hessian");
            c.init();
            X509CrlSignerEntry crlSigner = c.getCrlSigner("CASIGN.CRLSIGNER");
            System.out.println(crlSigner);

            X509CAEntry caEntry = c.getCA("RCA1");
            System.out.println(caEntry);
        }catch(Exception e)
        {
            e.printStackTrace();
        }
    }

}
