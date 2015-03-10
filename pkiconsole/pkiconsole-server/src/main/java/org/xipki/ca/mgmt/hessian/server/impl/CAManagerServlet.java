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

package org.xipki.ca.mgmt.hessian.server.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.mgmt.hessian.common.HessianCAManager;
import org.xipki.ca.mgmt.hessian.common.HessianCAMgmtException;
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
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.security.api.SecurityFactory;

import com.caucho.hessian.server.HessianServlet;

/**
 * @author Lijun Liao
 */

public class CAManagerServlet extends HessianServlet
implements HessianCAManager
{
    private static final Logger LOG = LoggerFactory.getLogger(CAManagerServlet.class);

    private static final long serialVersionUID = 1L;

    private CAManager caManager;
    private String truststoreFile;
    private String truststoreProvider;
    private String truststoreType = "PKCS12";
    private String truststorePassword;
    private SecurityFactory securityFactory;
    private Set<X509Certificate> trustedUserCerts = new HashSet<>();

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
    public void notifyCAChange()
    {
        caManager.notifyCAChange();
    }

    @Override
    public void addCaAlias(String aliasName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCaAlias(aliasName, caName);
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
    public Set<String> getCertprofileNames()
    {
        return caManager.getCertprofileNames();
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
    public Set<String> getCmpControlNames()
    {
        return caManager.getCmpControlNames();
    }

    @Override
    public Set<String> getCaNames()
    {
        return caManager.getCaNames();
    }

    @Override
    public void addCA(X509CAEntry newCaDbEntry)
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
    public X509CAEntry getCA(String caName)
    {
        return caManager.getCA(caName);
    }

    @Override
    public void changeCA(String name, CAStatus status,
            X509Certificate cert, Set<String> crl_uris,
            Set<String> delta_crl_uris, Set<String> ocsp_uris,
            CertValidity max_validity, String signer_type, String signer_conf,
            String crlsigner_name, String cmpcontrol_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCA(name, status, cert, crl_uris, delta_crl_uris, ocsp_uris,
                    max_validity, signer_type, signer_conf, crlsigner_name, cmpcontrol_name,
                    duplicate_key, duplicate_subject,
                    permissions, numCrls, expirationPeriod, validityMode);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCertprofileFromCA(String profileName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCertprofileFromCA(profileName, caName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addCertprofileToCA(String profileName, String caName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCertprofileToCA(profileName, caName);
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
    public Set<String> getCertprofilesForCA(String caName)
    {
        return caManager.getCertprofilesForCA(caName);
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
    public CertprofileEntry getCertprofile(String profileName)
    {
        return caManager.getCertprofile(profileName);
    }

    @Override
    public void removeCertprofile(String profileName)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCertprofile(profileName);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCertprofile(String name, String type, String conf)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCertprofile(name, type, conf);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void addCertprofile(CertprofileEntry dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCertprofile(dbEntry);
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
    public void addCrlSigner(X509CrlSignerEntry dbEntry)
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
            String signer_conf, String signer_cert, CRLControl crlControl)
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
    public X509CrlSignerEntry getCrlSigner(String name)
    {
        return caManager.getCrlSigner(name);
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
    public CmpControl getCmpControl(String name)
    {
        return caManager.getCmpControl(name);
    }

    @Override
    public void addCmpControl(CmpControl dbEntry)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.addCmpControl(dbEntry);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void removeCmpControl(String name)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.removeCmpControl(name);
        } catch (CAMgmtException e)
        {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void changeCmpControl(String name, Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert,
            Boolean sendResponderCert)
    throws HessianCAMgmtException
    {
        try
        {
            caManager.changeCmpControl(name, requireConfirmCert, requireMessageTime, messageTimeBias,
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
    public X509Certificate generateSelfSignedCA(String name, String certprofileName,
            byte[] p10Req, CAStatus status, long nextSerial, int nextCrlNo,
            List<String> crl_uris, List<String> delta_crl_uris,
            List<String> ocsp_uris, CertValidity max_validity, String signer_type,
            String signer_conf, String crlsigner_name, String cmpcontrol_name,
            DuplicationMode duplicate_key, DuplicationMode duplicate_subject,
            Set<Permission> permissions, int numCrls, int expirationPeriod,
            ValidityMode validityMode)
    throws HessianCAMgmtException
    {
        try
        {
            return caManager.generateSelfSignedCA(name, certprofileName, p10Req, status,
                    nextSerial, nextCrlNo,
                    crl_uris, delta_crl_uris, ocsp_uris, max_validity, signer_type, signer_conf,
                    crlsigner_name, cmpcontrol_name,
                    duplicate_key, duplicate_subject, permissions, numCrls,
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

    @Override
    public void service(ServletRequest request, ServletResponse response)
    throws IOException, ServletException
    {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        X509Certificate clientCert = (certs == null || certs.length < 1)? null : certs[0];

        if(clientCert == null)
        {
            String msg = "not authorizated (not in TLS session)";
            LOG.info(msg);
            throw new ServletException(msg);
        }

        if(trustedUserCerts.contains(clientCert) == false)
        {
            String msg = "untrusted TLS client certificate ";
            if(LOG.isInfoEnabled())
            {
                LOG.info(msg + "with subject='{}', issuer='{}' and serialNumber={}",
                        new Object[]{clientCert.getSubjectX500Principal().getName(),
                        clientCert.getIssuerX500Principal().getName(),
                        clientCert.getSerialNumber()});
            }
            throw new ServletException(msg);
        }

        super.service(request, response);
    }

    public void initialize()
    {
        if(truststoreFile == null)
        {
            LOG.error("truststoreFile is not set");
            return;
        }

        if(truststorePassword == null)
        {
            LOG.error("truststorePassword is not set");
            return;
        }

        try
        {
            String storePath = IoUtil.expandFilepath(truststoreFile);

            KeyStore keyStore;
            if(truststoreProvider == null || truststoreProvider.trim().length() == 0)
            {
                keyStore = KeyStore.getInstance(truststoreType);
            }
            else
            {
                keyStore = KeyStore.getInstance(truststoreType, truststoreProvider);
            }

            char[] password;
            if(securityFactory.getPasswordResolver() == null)
            {
                password = truststorePassword.toCharArray();
            }
            else
            {
                password = securityFactory.getPasswordResolver().resolvePassword(truststorePassword);
            }
            keyStore.load(new FileInputStream(storePath), password);
            Enumeration<String> aliases = keyStore.aliases();

            while(aliases.hasMoreElements())
            {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                if(cert instanceof X509Certificate)
                {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    trustedUserCerts.add(x509Cert);
                    if(LOG.isInfoEnabled())
                    {
                        LOG.info("added trusted user certificate with subject='{}', issuer='{}' and serialNumber={}",
                                new Object[]{x509Cert.getSubjectX500Principal().getName(),
                                        x509Cert.getIssuerX500Principal().getName(),
                                        x509Cert.getSerialNumber()});
                    }
                }
            }
        }catch(Exception e)
        {
            final String message = "Could not initialize CAManagerServlet";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    public void shutdown()
    {
        trustedUserCerts.clear();
    }

    public void setTruststoreFile(String truststoreFile)
    {
        this.truststoreFile = truststoreFile;
    }

    public void setTruststoreType(String truststoreType)
    {
        this.truststoreType = truststoreType;
    }

    public void setTruststoreProvider(String truststoreProvider)
    {
        this.truststoreProvider = truststoreProvider;
    }

    public void setTruststorePassword(String truststorePassword)
    {
        this.truststorePassword = truststorePassword;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

}
