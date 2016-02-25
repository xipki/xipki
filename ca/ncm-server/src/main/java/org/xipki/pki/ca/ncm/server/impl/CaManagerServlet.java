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

package org.xipki.pki.ca.ncm.server.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
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
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.CrlReason;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.pki.ca.ncm.common.HessianCaManager;
import org.xipki.pki.ca.ncm.common.HessianCaMgmtException;
import org.xipki.pki.ca.server.mgmt.api.AddUserEntry;
import org.xipki.pki.ca.server.mgmt.api.CaEntry;
import org.xipki.pki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.pki.ca.server.mgmt.api.CaManager;
import org.xipki.pki.ca.server.mgmt.api.CaMgmtException;
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

import com.caucho.hessian.server.HessianServlet;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerServlet extends HessianServlet implements HessianCaManager {

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerServlet.class);

    private static final long serialVersionUID = 1L;

    private CaManager caManager;

    private String truststoreFile;

    private String truststoreProvider;

    private String truststoreType = "PKCS12";

    private String truststorePassword;

    private SecurityFactory securityFactory;

    private Set<X509Certificate> trustedUserCerts = new HashSet<>();

    public CaManagerServlet() {
    }

    public void setCaManager(
            CaManager caManager) {
        this.caManager = caManager;
    }

    @Override
    public CaSystemStatus getCaSystemStatus() {
        return caManager.getCaSystemStatus();
    }

    @Override
    public boolean unlockCa() {
        return caManager.unlockCa();
    }

    @Override
    public boolean publishRootCa(
            final String caName,
            final String certprofile)
    throws HessianCaMgmtException {
        try {
            return caManager.publishRootCa(caName, certprofile);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean republishCertificates(
            final String caName,
            final List<String> publisherNames)
    throws HessianCaMgmtException {
        try {
            return caManager.republishCertificates(caName, publisherNames);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean clearPublishQueue(
            final String caName,
            final List<String> publisherNames)
    throws HessianCaMgmtException {
        try {
            return caManager.clearPublishQueue(caName, publisherNames);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCa(
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCa(caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean restartCaSystem() {
        return caManager.restartCaSystem();
    }

    @Override
    public boolean notifyCaChange()
    throws HessianCaMgmtException {
        try {
            return caManager.notifyCaChange();
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addCaAlias(
            final String aliasName,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.addCaAlias(aliasName, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCaAlias(
            final String aliasName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCaAlias(aliasName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public Set<String> getAliasesForCa(
            final String caName) {
        return caManager.getAliasesForCa(caName);
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
    public boolean addCa(
            final CaEntry newCaDbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addCa(newCaDbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public CaEntry getCa(
            final String caName) {
        return caManager.getCa(caName);
    }

    @Override
    public boolean changeCa(
            final ChangeCaEntry changeCAentry)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCa(changeCAentry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCertprofileFromCa(
            final String profileName,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCertprofileFromCa(profileName, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addCertprofileToCa(
            final String profileName,
            final String profileLocalname,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.addCertprofileToCa(profileName, profileLocalname, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removePublisherFromCa(
            final String publisherName,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.removePublisherFromCa(publisherName, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addPublisherToCa(
            final String publisherName,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.addPublisherToCa(publisherName, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public Map<String, String> getCertprofilesForCa(
            final String caName) {
        return caManager.getCertprofilesForCa(caName);
    }

    @Override
    public Set<CaHasRequestorEntry> getCmpRequestorsForCa(
            final String caName) {
        return caManager.getCmpRequestorsForCa(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        return caManager.getCmpRequestor(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addCmpRequestor(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCmpRequestor(requestorName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCmpRequestor(name, base64Cert);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCmpRequestorFromCa(
            final String requestorName,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCmpRequestorFromCa(requestorName, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addCmpRequestorToCa(
            final CaHasRequestorEntry requestor,
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.addCmpRequestorToCa(requestor, caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
    throws HessianCaMgmtException {
        try {
            return caManager.removeCertprofile(profileName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCertprofile(name, type, conf);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addCertprofile(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addCmpResponder(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCmpResponder(name);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCmpResponder(name, type, conf, base64Cert);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public CmpResponderEntry getCmpResponder(String name) {
        return caManager.getCmpResponder(name);
    }

    @Override
    public boolean addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addCrlSigner(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCrlSigner(
            final String crlSignerName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCrlSigner(crlSignerName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCrlSigner(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
    throws HessianCaMgmtException {
        try {
            return caManager.addPublisher(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public List<PublisherEntry> getPublishersForCa(
            final String caName) {
        return caManager.getPublishersForCa(caName);
    }

    @Override
    public PublisherEntry getPublisher(
            final String publisherName) {
        return caManager.getPublisher(publisherName);
    }

    @Override
    public boolean removePublisher(
            final String publisherName)
    throws HessianCaMgmtException {
        try {
            return caManager.removePublisher(publisherName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws HessianCaMgmtException {
        try {
            return caManager.changePublisher(name, type, conf);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
    throws HessianCaMgmtException {
        try {
            return caManager.addCmpControl(dbEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCmpControl(
            final String name)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCmpControl(name);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws HessianCaMgmtException {
        try {
            return caManager.changeCmpControl(name, conf);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
    throws HessianCaMgmtException {
        try {
            return caManager.addEnvParam(name, value);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeEnvParam(
            final String envParamName)
    throws HessianCaMgmtException {
        try {
            return caManager.removeEnvParam(envParamName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeEnvParam(
            final String name,
            final String value)
    throws HessianCaMgmtException {
        try {
            return caManager.changeEnvParam(name, value);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws HessianCaMgmtException {
        try {
            return caManager.revokeCa(caName, revocationInfo);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean unrevokeCa(
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.unrevokeCa(caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CrlReason reason,
            final Date invalidityTime)
    throws HessianCaMgmtException {
        try {
            return caManager.revokeCertificate(caName, serialNumber, reason, invalidityTime);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws HessianCaMgmtException {
        try {
            return caManager.unrevokeCertificate(caName, serialNumber);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws HessianCaMgmtException {
        try {
            return caManager.removeCertificate(caName, serialNumber);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public byte[] generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws HessianCaMgmtException {
        try {
            X509Certificate cert = caManager.generateCertificate(caName, profileName, user,
                    encodedPkcs10Request);
            return cert.getEncoded();
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        } catch (CertificateEncodingException ex) {
            throw new HessianCaMgmtException("could not encode generated certificate: "
                    + ex.getMessage());
        }
    }

    @Override
    public X509Certificate generateSelfSignedCa(
            final X509CaEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws HessianCaMgmtException {
        try {
            return caManager.generateRootCa(caEntry, certprofileName, p10Req);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
    throws HessianCaMgmtException {
        try {
            return caManager.addUser(userEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws HessianCaMgmtException {
        try {
            return caManager.getUser(username);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws HessianCaMgmtException {
        try {
            return caManager.changeUser(username, password, cnRegex);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeUser(
            final String username)
    throws HessianCaMgmtException {
        try {
            return caManager.removeUser(username);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public X509CRL generateCrlOnDemand(
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.generateCrlOnDemand(caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public X509CRL getCrl(
            final String caName,
            final BigInteger crlNumber)
    throws HessianCaMgmtException {
        try {
            return caManager.getCrl(caName, crlNumber);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public X509CRL getCurrentCrl(
            final String caName)
    throws HessianCaMgmtException {
        try {
            return caManager.getCurrentCrl(caName);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean addScep(
            final ScepEntry scepEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.addScep(scepEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean removeScep(
            final String name)
    throws HessianCaMgmtException {
        try {
            return caManager.removeScep(name);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws HessianCaMgmtException {
        try {
            return caManager.changeScep(scepEntry);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
        }
    }

    @Override
    public Set<String> getScepNames() {
        return caManager.getScepNames();
    }

    @Override
    public ScepEntry getScepEntry(
            final String name)
    throws HessianCaMgmtException {
        try {
            return caManager.getScepEntry(name);
        } catch (CaMgmtException ex) {
            throw new HessianCaMgmtException(ex.getMessage());
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
                    } // end if
                } // end if
            } // end while
        } catch (Exception ex) {
            final String message = "could not initialize CAManagerServlet";
            if (LOG.isErrorEnabled()) {
                LOG.error(LogUtil.buildExceptionLogFormat(message), ex.getClass().getName(),
                        ex.getMessage());
            }
            LOG.debug(message, ex);
        }
    } // method initialize

    public void shutdown() {
        trustedUserCerts.clear();
    }

    public void setTruststoreFile(
            final String truststoreFile) {
        this.truststoreFile = truststoreFile;
    }

    public void setTruststoreType(
            final String truststoreType) {
        this.truststoreType = truststoreType;
    }

    public void setTruststoreProvider(
            final String truststoreProvider) {
        this.truststoreProvider = truststoreProvider;
    }

    public void setTruststorePassword(
            final String truststorePassword) {
        this.truststorePassword = truststorePassword;
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

}
