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

package org.xipki.pki.ca.ncm.server.impl;

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
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pki.ca.ncm.common.HessianCAManager;
import org.xipki.pki.ca.ncm.common.HessianCAMgmtException;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CAEntry;
import org.xipki.pki.ca.server.mgmt.api.CAHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CAManager;
import org.xipki.pki.ca.server.mgmt.api.CAMgmtException;
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
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.SecurityFactory;

import com.caucho.hessian.server.HessianServlet;

/**
 * @author Lijun Liao
 */

public class CAManagerServlet extends HessianServlet implements HessianCAManager {

    private static final Logger LOG = LoggerFactory.getLogger(CAManagerServlet.class);

    private static final long serialVersionUID = 1L;

    private CAManager caManager;

    private String truststoreFile;

    private String truststoreProvider;

    private String truststoreType = "PKCS12";

    private String truststorePassword;

    private SecurityFactory securityFactory;

    private Set<X509Certificate> trustedUserCerts = new HashSet<>();

    public CAManagerServlet() {
    }

    public void setCaManager(
            CAManager caManager) {
        this.caManager = caManager;
    }

    @Override
    public CASystemStatus getCASystemStatus() {
        return caManager.getCASystemStatus();
    }

    @Override
    public boolean unlockCA() {
        return caManager.unlockCA();
    }

    @Override
    public boolean publishRootCA(
            final String caName,
            final String certprofile)
    throws HessianCAMgmtException {
        try {
            return caManager.publishRootCA(caName, certprofile);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean republishCertificates(
            final String caName,
            final List<String> publisherNames)
    throws HessianCAMgmtException {
        try {
            return caManager.republishCertificates(caName, publisherNames);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean clearPublishQueue(
            final String caName,
            final List<String> publisherNames)
    throws HessianCAMgmtException {
        try {
            return caManager.clearPublishQueue(caName, publisherNames);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCA(
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCA(caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean restartCaSystem() {
        return caManager.restartCaSystem();
    }

    @Override
    public boolean notifyCAChange()
    throws HessianCAMgmtException {
        try {
            return caManager.notifyCAChange();
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addCaAlias(
            final String aliasName,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.addCaAlias(aliasName, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCaAlias(
            final String aliasName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCaAlias(aliasName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Set<String> getAliasesForCA(
            final String caName) {
        return caManager.getAliasesForCA(caName);
    }

    @Override
    public String getCaName(
            final String aliasName) {
        return caManager.getCaNameForAlias(aliasName);
    }

    @Override
    public Set<String> getCaAliasNames() {
        return caManager.getCaAliasNames();
    }

    @Override
    public Set<String> getCertprofileNames() {
        return caManager.getCertprofileNames();
    }

    @Override
    public Set<String> getPublisherNames() {
        return caManager.getPublisherNames();
    }

    @Override
    public Set<String> getCmpRequestorNames() {
        return caManager.getCmpRequestorNames();
    }

    @Override
    public Set<String> getCmpResponderNames() {
        return caManager.getCmpResponderNames();
    }

    @Override
    public Set<String> getCrlSignerNames() {
        return caManager.getCrlSignerNames();
    }

    @Override
    public Set<String> getCmpControlNames() {
        return caManager.getCmpControlNames();
    }

    @Override
    public Set<String> getCaNames() {
        return caManager.getCaNames();
    }

    @Override
    public boolean addCA(
            final CAEntry newCaDbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCA(newCaDbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CAEntry getCA(
            final String caName) {
        return caManager.getCA(caName);
    }

    @Override
    public boolean changeCA(
            final ChangeCAEntry changeCAentry)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCA(changeCAentry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCertprofileFromCA(
            final String profileName,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCertprofileFromCA(profileName, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addCertprofileToCA(
            final String profileName,
            final String profileLocalname,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.addCertprofileToCA(profileName, profileLocalname, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removePublisherFromCA(
            final String publisherName,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.removePublisherFromCA(publisherName, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addPublisherToCA(
            final String publisherName,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.addPublisherToCA(publisherName, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Map<String, String> getCertprofilesForCA(
            final String caName) {
        return caManager.getCertprofilesForCA(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(
            final String caName) {
        return caManager.getCmpRequestorsForCA(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        return caManager.getCmpRequestor(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCmpRequestor(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCmpRequestor(requestorName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCmpRequestor(name, base64Cert);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCmpRequestorFromCA(
            final String requestorName,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCmpRequestorFromCA(requestorName, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addCmpRequestorToCA(
            final CAHasRequestorEntry requestor,
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.addCmpRequestorToCA(requestor, caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CertprofileEntry getCertprofile(
            final String profileName) {
        return caManager.getCertprofile(profileName);
    }

    @Override
    public boolean removeCertprofile(
            final String profileName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCertprofile(profileName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCertprofile(name, type, conf);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCertprofile(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCmpResponder(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCmpResponder(name);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCmpResponder(name, type, conf, base64Cert);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CmpResponderEntry getCmpResponder(String name) {
        return caManager.getCmpResponder(name);
    }

    @Override
    public boolean addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCrlSigner(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCrlSigner(
            final String crlSignerName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCrlSigner(crlSignerName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCrlSigner(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public X509CrlSignerEntry getCrlSigner(
            final String name) {
        return caManager.getCrlSigner(name);
    }

    @Override
    public boolean addPublisher(
            final PublisherEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addPublisher(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(
            final String caName) {
        return caManager.getPublishersForCA(caName);
    }

    @Override
    public PublisherEntry getPublisher(
            final String publisherName) {
        return caManager.getPublisher(publisherName);
    }

    @Override
    public boolean removePublisher(
            final String publisherName)
    throws HessianCAMgmtException {
        try {
            return caManager.removePublisher(publisherName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws HessianCAMgmtException {
        try {
            return caManager.changePublisher(name, type, conf);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public CmpControlEntry getCmpControl(
            final String name) {
        return caManager.getCmpControl(name);
    }

    @Override
    public boolean addCmpControl(
            final CmpControlEntry dbEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addCmpControl(dbEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCmpControl(
            final String name)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCmpControl(name);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws HessianCAMgmtException {
        try {
            return caManager.changeCmpControl(name, conf);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Set<String> getEnvParamNames() {
        return caManager.getEnvParamNames();
    }

    @Override
    public String getEnvParam(
            final String name) {
        return caManager.getEnvParam(name);
    }

    @Override
    public boolean addEnvParam(
            final String name,
            final String value)
    throws HessianCAMgmtException {
        try {
            return caManager.addEnvParam(name, value);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeEnvParam(
            final String envParamName)
    throws HessianCAMgmtException {
        try {
            return caManager.removeEnvParam(envParamName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeEnvParam(
            final String name,
            final String value)
    throws HessianCAMgmtException {
        try {
            return caManager.changeEnvParam(name, value);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws HessianCAMgmtException {
        try {
            return caManager.revokeCa(caName, revocationInfo);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean unrevokeCa(
            final String caName)
    throws HessianCAMgmtException {
        try {
            return caManager.unrevokeCa(caName);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CRLReason reason,
            final Date invalidityTime)
    throws HessianCAMgmtException {
        try {
            return caManager.revokeCertificate(caName, serialNumber, reason, invalidityTime);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws HessianCAMgmtException {
        try {
            return caManager.unrevokeCertificate(caName, serialNumber);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws HessianCAMgmtException {
        try {
            return caManager.removeCertificate(caName, serialNumber);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public byte[] generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws HessianCAMgmtException {
        try {
            X509Certificate cert = caManager.generateCertificate(caName, profileName, user,
                    encodedPkcs10Request);
            return cert.getEncoded();
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        } catch (CertificateEncodingException e) {
            throw new HessianCAMgmtException("could not encode generated certificate: "
                    + e.getMessage());
        }
    }

    @Override
    public X509Certificate generateSelfSignedCA(
            final X509CAEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws HessianCAMgmtException {
        try {
            return caManager.generateRootCA(caEntry, certprofileName, p10Req);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public String getAttribute(
            final String attributeKey) {
        if ("version".equalsIgnoreCase(attributeKey)) {
            return "1";
        }
        return null;
    }

    @Override
    public boolean addUser(
            final AddUserEntry userEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addUser(userEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws HessianCAMgmtException {
        try {
            return caManager.getUser(username);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws HessianCAMgmtException {
        try {
            return caManager.changeUser(username, password, cnRegex);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeUser(
            final String username)
    throws HessianCAMgmtException {
        try {
            return caManager.removeUser(username);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean addScep(
            final ScepEntry scepEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.addScep(scepEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean removeScep(
            final String name)
    throws HessianCAMgmtException {
        try {
            return caManager.removeScep(name);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws HessianCAMgmtException {
        try {
            return caManager.changeScep(scepEntry);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public Set<String> getScepNames() {
        return caManager.getScepNames();
    }

    @Override
    public ScepEntry getScepEntry(
            final String name)
    throws HessianCAMgmtException {
        try {
            return caManager.getScepEntry(name);
        } catch (CAMgmtException e) {
            throw new HessianCAMgmtException(e.getMessage());
        }
    }

    @Override
    public void service(
            final ServletRequest request,
            final ServletResponse response)
    throws IOException, ServletException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(
                "javax.servlet.request.X509Certificate");
        X509Certificate clientCert = (certs == null || certs.length < 1)
                ? null
                : certs[0];

        if (clientCert == null) {
            String msg = "not authorizated (not in TLS session)";
            LOG.info(msg);
            throw new ServletException(msg);
        }

        if (!trustedUserCerts.contains(clientCert)) {
            String msg = "untrusted TLS client certificate ";
            if (LOG.isInfoEnabled()) {
                LOG.info(msg + "with subject='{}', issuer='{}' and serialNumber={}",
                        new Object[]{clientCert.getSubjectX500Principal().getName(),
                        clientCert.getIssuerX500Principal().getName(),
                        clientCert.getSerialNumber()});
            }
            throw new ServletException(msg);
        }

        super.service(request, response);
    }

    public void initialize() {
        if (truststoreFile == null) {
            LOG.error("truststoreFile is not set");
            return;
        }

        if (truststorePassword == null) {
            LOG.error("truststorePassword is not set");
            return;
        }

        try {
            String storePath = IoUtil.expandFilepath(truststoreFile);

            KeyStore keyStore;
            if (truststoreProvider == null || truststoreProvider.trim().length() == 0) {
                keyStore = KeyStore.getInstance(truststoreType);
            } else {
                keyStore = KeyStore.getInstance(truststoreType, truststoreProvider);
            }

            char[] password;
            if (securityFactory.getPasswordResolver() == null) {
                password = truststorePassword.toCharArray();
            } else {
                password = securityFactory.getPasswordResolver().resolvePassword(
                        truststorePassword);
            }
            keyStore.load(new FileInputStream(storePath), password);
            Enumeration<String> aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    trustedUserCerts.add(x509Cert);
                    if (LOG.isInfoEnabled()) {
                        LOG.info("added trusted user certificate with subject='{}', issuer='{}'"
                                + " and serialNumber={}",
                                new Object[]{x509Cert.getSubjectX500Principal().getName(),
                                        x509Cert.getIssuerX500Principal().getName(),
                                        x509Cert.getSerialNumber()});
                    }
                }
            }
        } catch (Exception e) {
            final String message = "could not initialize CAManagerServlet";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(),
                        e.getMessage());
            }
            LOG.debug(message, e);
        }
    }

    public void shutdown() {
        trustedUserCerts.clear();
    }

    public  void setTruststoreFile(
            final String truststoreFile) {
        this.truststoreFile = truststoreFile;
    }

    public  void setTruststoreType(
            final String truststoreType) {
        this.truststoreType = truststoreType;
    }

    public  void setTruststoreProvider(
            final String truststoreProvider) {
        this.truststoreProvider = truststoreProvider;
    }

    public  void setTruststorePassword(
            final String truststorePassword) {
        this.truststorePassword = truststorePassword;
    }

    public  void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

}
