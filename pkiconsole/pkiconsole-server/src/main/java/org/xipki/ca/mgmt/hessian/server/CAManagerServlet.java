/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.mgmt.hessian.server;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.xipki.ca.common.CAMgmtException;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.CmpControl;
import org.xipki.ca.mgmt.hessian.common.HessianCAManager;
import org.xipki.ca.mgmt.hessian.common.HessianCAMgmtException;
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

import com.caucho.hessian.server.HessianServlet;

/**
 * @author Lijun Liao
 */

public class CAManagerServlet extends HessianServlet
implements HessianCAManager
{
    private static final long serialVersionUID = 1L;

    private CAManager caManager;

    public CAManagerServlet()
    {
    }

    public void setCaManager(CAManager caManager)
    {
        this.caManager = caManager;
    }

    @Override
    public CASystemStatus getCASystemStatus()
    {
        return caManager.getCASystemStatus();
    }

    @Override
    public boolean unlockCA()
    {
        return caManager.unlockCA();
    }

    @Override
    public void publishRootCA(String caName, String certprofile)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.publishRootCA(caName, certprofile);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean republishCertificates(String caName, List<String> publisherNames)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.republishCertificates(caName, publisherNames);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.clearPublishQueue(caName, publisherNames);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCA(String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCA(caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean restartCaSystem()
    {
        return caManager.restartCaSystem();
    }

    @Override
    public void addCaAlias(String aliasName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCaAlias(aliasName, caName);
            throw new CAMgmtException("TESTBUG");
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCaAlias(String aliasName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCaAlias(aliasName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public String getAliasName(String caName)
    {
        return caManager.getAliasName(caName);
    }

    @Override
    public String getCaName(String aliasName)
    {
        return caManager.getCaName(aliasName);
    }

    @Override
    public Set<String> getCaAliasNames()
    {
        return caManager.getCaAliasNames();
    }

    @Override
    public Set<String> getCertProfileNames()
    {
        return caManager.getCertProfileNames();
    }

    @Override
    public Set<String> getPublisherNames()
    {
        return caManager.getPublisherNames();
    }

    @Override
    public Set<String> getCmpRequestorNames()
    {
        return caManager.getCmpRequestorNames();
    }

    @Override
    public Set<String> getCrlSignerNames()
    {
        return caManager.getCrlSignerNames();
    }

    @Override
    public Set<String> getCANames()
    {
        return caManager.getCANames();
    }

    @Override
    public void addCA(CAEntry newCaDbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCA(newCaDbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CAEntry getCA(String caName)
    {
        return caManager.getCA(caName);
    }

    @Override
    public void changeCA(String name, CAStatus status, Long nextSerial,
            byte[] encodedCert, Set<String> crl_uris,
            Set<String> delta_crl_uris, Set<String> ocsp_uris,
            Integer max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws HessianCAMgmtException
    {
        X509Certificate cert;
        try
        {
            cert = IoCertUtil.parseCert(encodedCert);
        } catch (CertificateException | IOException e)
        {
            throw new HessianCAMgmtException("could not parse certificate: " + e.getMessage());
        }

        try
        {
            caManager.changeCA(name, status, nextSerial, cert, crl_uris, delta_crl_uris, ocsp_uris,
                    max_validity, signer_type, signer_conf, crlsigner_name, duplicate_key, duplicate_subject,
                    permissions, numCrls, expirationPeriod, validityMode);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCertProfileFromCA(String profileName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCertProfileFromCA(profileName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addCertProfileToCA(String profileName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCertProfileToCA(profileName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removePublisherFromCA(String publisherName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removePublisherFromCA(publisherName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addPublisherToCA(String publisherName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addPublisherToCA(publisherName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Set<String> getCertProfilesForCA(String caName)
    {
        return caManager.getCertProfilesForCA(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName)
    {
        return caManager.getCmpRequestorsForCA(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(String name)
    {
        return caManager.getCmpRequestor(name);
    }

    @Override
    public void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCmpRequestor(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCmpRequestor(String requestorName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCmpRequestor(requestorName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCmpRequestor(String name, String cert)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCmpRequestor(name, cert);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCmpRequestorFromCA(String requestorName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCmpRequestorFromCA(requestorName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCmpRequestorToCA(requestor, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CertProfileEntry getCertProfile(String profileName)
    {
        return caManager.getCertProfile(profileName);
    }

    @Override
    public void removeCertProfile(String profileName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCertProfile(profileName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCertProfile(String name, String type, String conf)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCertProfile(name, type, conf);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addCertProfile(CertProfileEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCertProfile(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void setCmpResponder(CmpResponderEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.setCmpResponder(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCmpResponder()
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCmpResponder();
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCmpResponder(String type, String conf, String cert)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCmpResponder(type, conf, cert);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CmpResponderEntry getCmpResponder()
    {
        return caManager.getCmpResponder();
    }

    @Override
    public void addCrlSigner(CrlSignerEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCrlSigner(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCrlSigner(String crlSignerName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCrlSigner(crlSignerName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCrlSigner(String name, String signer_type,
            String signer_conf, String signer_cert, String crlControl)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCrlSigner(name, signer_type, signer_conf, signer_cert, crlControl);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CrlSignerEntry getCrlSigner(String name)
    {
        return caManager.getCrlSigner(name);
    }

    @Override
    public void setCrlSignerInCA(String crlSignerName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.setCrlSignerInCA(crlSignerName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addPublisher(PublisherEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addPublisher(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(String caName)
    {
        return caManager.getPublishersForCA(caName);
    }

    @Override
    public PublisherEntry getPublisher(String publisherName)
    {
        return caManager.getPublisher(publisherName);
    }

    @Override
    public void removePublisher(String publisherName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removePublisher(publisherName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changePublisher(String name, String type, String conf)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changePublisher(name, type, conf);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CmpControl getCmpControl()
    {
        return caManager.getCmpControl();
    }

    @Override
    public void setCmpControl(CmpControl dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.setCmpControl(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCmpControl()
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCmpControl();
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert,
            Boolean sendResponderCert)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCmpControl(requireConfirmCert, requireMessageTime, messageTimeBias,
                    confirmWaitTime, sendCaCert, sendResponderCert);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Set<String> getEnvParamNames()
    {
        return caManager.getEnvParamNames();
    }

    @Override
    public String getEnvParam(String name)
    {
        return caManager.getEnvParam(name);
    }

    @Override
    public void addEnvParam(String name, String value)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addEnvParam(name, value);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeEnvParam(String envParamName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeEnvParam(envParamName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeEnvParam(String name, String value)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeEnvParam(name, value);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.revokeCa(caName, revocationInfo);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void unrevokeCa(String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.unrevokeCa(caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean revokeCertificate(String caName, BigInteger serialNumber,
            CRLReason reason, Date invalidityTime)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.revokeCertificate(caName, serialNumber, reason, invalidityTime);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.unrevokeCertificate(caName, serialNumber);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCertificate(String caName, BigInteger serialNumber)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.removeCertificate(caName, serialNumber);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public byte[] generateCertificate(String caName, String profileName,
            String user, byte[] encodedPkcs10Request)
    throws HessianCAMgmtException
    {
        try
        {
            X509Certificate cert = caManager.generateCertificate(caName, profileName, user, encodedPkcs10Request);
            return cert.getEncoded();
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        } catch (CertificateEncodingException e)
        {
            throw new HessianCAMgmtException("Could not encode generated certificate: " + e.getMessage());
        }
    }

    @Override
    public byte[] generateSelfSignedCA(String name, String certprofileName,
            String subject, CAStatus status, long nextSerial,
            List<String> crl_uris, List<String> delta_crl_uris,
            List<String> ocsp_uris, int max_validity, String signer_type,
            String signer_conf, String crlsigner_name,
            DuplicationMode duplicate_key, DuplicationMode duplicate_subject,
            Set<Permission> permissions, int numCrls, int expirationPeriod,
            ValidityMode validityMode)
    throws HessianCAMgmtException
    {
        try
        {
            return generateSelfSignedCA(name, certprofileName, subject, status, nextSerial,
                    crl_uris, delta_crl_uris, ocsp_uris, max_validity, signer_type, signer_conf,
                    crlsigner_name, duplicate_key, duplicate_subject, permissions, numCrls,
                    expirationPeriod, validityMode);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public String getAttribute(String attributeKey)
    {
        if("version".equalsIgnoreCase(attributeKey))
        {
            return "1";
        }
        return null;
    }

}
