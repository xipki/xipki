/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.mgmt.hessian.client;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.common.CAMgmtException;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.CmpControl;
import org.xipki.ca.mgmt.hessian.common.HessianCAManager;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.CAManager;
import org.xipki.ca.server.mgmt.api.CertProfileEntry;
import org.xipki.ca.server.mgmt.api.CmpRequestorEntry;
import org.xipki.ca.server.mgmt.api.CmpResponderEntry;
import org.xipki.ca.server.mgmt.api.CrlSignerEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.PublisherEntry;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.IoCertUtil;

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
        HessianProxyFactory factory = new HessianProxyFactory();
        factory.setHessian2Request(true);
        factory.setHessian2Reply(true);

        this.client = (HessianCAManager) factory.create(
                HessianCAManager.class, serverURL, getClass().getClassLoader());
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
    public Set<String> getCertProfileNames()
    {
        return client.getCertProfileNames();
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
    public Set<String> getCANames()
    {
        return client.getCANames();
    }

    @Override
    public void addCA(CAEntry newCaDbEntry)
    throws CAMgmtException
    {
        client.addCA(newCaDbEntry);
    }

    @Override
    public CAEntry getCA(String caName)
    {
        return client.getCA(caName);
    }

    @Override
    public void changeCA(String name, CAStatus status, Long nextSerial,
            X509Certificate cert, Set<String> crl_uris,
            Set<String> delta_crl_uris, Set<String> ocsp_uris,
            Integer max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        byte[] encodedCert;
        try
        {
            encodedCert = cert.getEncoded();
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException("Could not encode the certificate", e);
        }

        client.changeCA(name, status, nextSerial, encodedCert, crl_uris, delta_crl_uris, ocsp_uris,
                max_validity, signer_type, signer_conf, crlsigner_name, duplicate_key, duplicate_subject,
                permissions, numCrls, expirationPeriod, validityMode);
    }

    @Override
    public void removeCertProfileFromCA(String profileName, String caName)
    throws CAMgmtException
    {
        client.removeCertProfileFromCA(profileName, caName);
    }

    @Override
    public void addCertProfileToCA(String profileName, String caName)
    throws CAMgmtException
    {
        client.addCertProfileToCA(profileName, caName);
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
    public Set<String> getCertProfilesForCA(String caName)
    {
        return client.getCertProfilesForCA(caName);
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
    public CertProfileEntry getCertProfile(String profileName)
    {
        return client.getCertProfile(profileName);
    }

    @Override
    public void removeCertProfile(String profileName)
    throws CAMgmtException
    {
        client.removeCertProfile(profileName);
    }

    @Override
    public void changeCertProfile(String name, String type, String conf)
    throws CAMgmtException
    {
        client.changeCertProfile(name, type, conf);
    }

    @Override
    public void addCertProfile(CertProfileEntry dbEntry)
    throws CAMgmtException
    {
        client.addCertProfile(dbEntry);
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
    public void addCrlSigner(CrlSignerEntry dbEntry)
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
            String signer_conf, String signer_cert, String crlControl)
    throws CAMgmtException
    {
        client.changeCrlSigner(name, signer_type, signer_conf, signer_cert, crlControl);
    }

    @Override
    public CrlSignerEntry getCrlSigner(String name)
    {
        return client.getCrlSigner(name);
    }

    @Override
    public void setCrlSignerInCA(String crlSignerName, String caName)
    throws CAMgmtException
    {
        client.setCrlSignerInCA(crlSignerName, caName);
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
    public CmpControl getCmpControl()
    {
        return client.getCmpControl();
    }

    @Override
    public void setCmpControl(CmpControl dbEntry)
    throws CAMgmtException
    {
        client.setCmpControl(dbEntry);
    }

    @Override
    public void removeCmpControl()
    throws CAMgmtException
    {
        client.removeCmpControl();
    }

    @Override
    public void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert,
            Boolean sendResponderCert)
    throws CAMgmtException
    {
        client.changeCmpControl(requireConfirmCert, requireMessageTime, messageTimeBias,
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
            return IoCertUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new CAMgmtException("Could not parse the certificate: " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate generateSelfSignedCA(String name,
            String certprofileName, String subject, CAStatus status,
            long nextSerial, List<String> crl_uris,
            List<String> delta_crl_uris, List<String> ocsp_uris,
            int max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException
    {
        byte[] encodedCert = client.generateSelfSignedCA(name, certprofileName, subject, status,
                nextSerial, crl_uris, delta_crl_uris, ocsp_uris, max_validity,
                signer_type, signer_conf, crlsigner_name, duplicate_key, duplicate_subject,
                permissions, numCrls, expirationPeriod, validityMode);

        try
        {
            return IoCertUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new CAMgmtException("Could not parse the certificate: " + e.getMessage(), e);
        }
    }

}
