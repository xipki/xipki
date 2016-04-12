/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.pki.ca.ncm.client.impl;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.CertRevocationInfo;
import org.xipki.commons.security.api.CrlReason;
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
import org.xipki.pki.ca.server.mgmt.api.UserEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.ScepEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CaEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509ChangeCrlSignerEntry;
import org.xipki.pki.ca.server.mgmt.api.x509.X509CrlSignerEntry;

import com.caucho.hessian.client.HessianProxyFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CaManagerClient implements CaManager {

    private static final Logger LOG = LoggerFactory.getLogger(CaManagerClient.class);

    private HessianCaManager client;

    private int version;

    private String serverUrl;

    public CaManagerClient() {
    }

    public void init()
    throws Exception {
        if (serverUrl == null) {
            throw new IllegalStateException("serverUrl is not set");
        }
        HessianProxyFactory factory = new HessianProxyFactory(getClass().getClassLoader());
        factory.setHessian2Request(true);
        factory.setHessian2Reply(true);

        this.client = (HessianCaManager) factory.create(
                HessianCaManager.class, serverUrl);
        determineServerVersion();
    }

    public void shutdown()
    throws Exception {
    }

    public void setServerUrl(
            final String serverUrl) {
        this.serverUrl = ParamUtil.requireNonNull("severUrl", serverUrl);
    }

    private void determineServerVersion() {
        String versionS = client.getAttribute("version");
        if (versionS == null) {
            version = 0;
        } else {
            try {
                version = Integer.parseInt(versionS);
            } catch (NumberFormatException ex) {
                LOG.info("invalid version {}, reset it to 0", versionS);
            }
        }
        LOG.info("set version to {}", version);
    }

    @Override
    public CaSystemStatus getCaSystemStatus() {
        return client.getCaSystemStatus();
    }

    @Override
    public boolean unlockCa() {
        return client.unlockCa();
    }

    @Override
    public boolean publishRootCa(
            final String caName,
            final String certprofile)
    throws CaMgmtException {
        return client.publishRootCa(caName, certprofile);
    }

    @Override
    public boolean republishCertificates(
            final String caName,
            final List<String> publisherNames)
    throws CaMgmtException {
        return client.republishCertificates(caName, publisherNames);
    }

    @Override
    public boolean clearPublishQueue(
            final String caName,
            final List<String> publisherNames)
    throws CaMgmtException {
        return client.clearPublishQueue(caName, publisherNames);
    }

    @Override
    public boolean removeCa(
            final String caName)
    throws CaMgmtException {
        return client.removeCa(caName);
    }

    @Override
    public boolean restartCaSystem() {
        return client.restartCaSystem();
    }

    @Override
    public boolean notifyCaChange()
    throws HessianCaMgmtException {
        return client.notifyCaChange();
    }

    @Override
    public boolean addCaAlias(
            final String aliasName,
            final String caName)
    throws CaMgmtException {
        return client.addCaAlias(aliasName, caName);
    }

    @Override
    public boolean removeCaAlias(
            final String aliasName)
    throws CaMgmtException {
        return client.removeCaAlias(aliasName);
    }

    @Override
    public Set<String> getAliasesForCa(
            final String caName) {
        return client.getAliasesForCa(caName);
    }

    @Override
    public String getCaNameForAlias(
            final String aliasName) {
        return client.getCaNameForAlias(aliasName);
    }

    @Override
    public Set<String> getCaAliasNames() {
        return client.getCaAliasNames();
    }

    @Override
    public Set<String> getCertprofileNames() {
        return client.getCertprofileNames();
    }

    @Override
    public Set<String> getPublisherNames() {
        return client.getPublisherNames();
    }

    @Override
    public Set<String> getCmpRequestorNames() {
        return client.getCmpRequestorNames();
    }

    @Override
    public Set<String> getCmpResponderNames() {
        return client.getCmpResponderNames();
    }

    @Override
    public Set<String> getCrlSignerNames() {
        return client.getCrlSignerNames();
    }

    @Override
    public Set<String> getCmpControlNames() {
        return client.getCmpControlNames();
    }

    @Override
    public Set<String> getCaNames() {
        return client.getCaNames();
    }

    @Override
    public boolean addCa(
            final CaEntry newCaDbEntry)
    throws CaMgmtException {
        return client.addCa(newCaDbEntry);
    }

    @Override
    public CaEntry getCa(
            final String caName) {
        return client.getCa(caName);
    }

    @Override
    public boolean changeCa(
            final ChangeCaEntry changeCAentry)
    throws CaMgmtException {
        return client.changeCa(changeCAentry);
    }

    @Override
    public boolean removeCertprofileFromCa(
            final String profileName,
            final String caName)
    throws CaMgmtException {
        return client.removeCertprofileFromCa(profileName, caName);
    }

    @Override
    public boolean addCertprofileToCa(
            final String profileName,
            final String caName)
    throws CaMgmtException {
        return client.addCertprofileToCa(profileName, caName);
    }

    @Override
    public boolean removePublisherFromCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        return client.removePublisherFromCa(publisherName, caName);
    }

    @Override
    public boolean addPublisherToCa(
            final String publisherName,
            final String caName)
    throws CaMgmtException {
        return client.addPublisherToCa(publisherName, caName);
    }

    @Override
    public Set<String> getCertprofilesForCa(
            final String caName) {
        return client.getCertprofilesForCa(caName);
    }

    @Override
    public Set<CaHasRequestorEntry> getCmpRequestorsForCa(
            final String caName) {
        return client.getCmpRequestorsForCa(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        return client.getCmpRequestor(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CaMgmtException {
        return client.addCmpRequestor(dbEntry);
    }

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws CaMgmtException {
        return client.removeCmpRequestor(requestorName);
    }

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CaMgmtException {
        return client.changeCmpRequestor(name, base64Cert);
    }

    @Override
    public boolean removeCmpRequestorFromCa(
            final String requestorName,
            final String caName)
    throws CaMgmtException {
        return client.removeCmpRequestorFromCa(requestorName, caName);
    }

    @Override
    public boolean addCmpRequestorToCa(
            final CaHasRequestorEntry requestor,
            final String caName)
    throws CaMgmtException {
        return client.addCmpRequestorToCa(requestor, caName);
    }

    @Override
    public CertprofileEntry getCertprofile(
            final String profileName) {
        return client.getCertprofile(profileName);
    }

    @Override
    public boolean removeCertprofile(
            final String profileName)
    throws CaMgmtException {
        return client.removeCertprofile(profileName);
    }

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws CaMgmtException {
        return client.changeCertprofile(name, type, conf);
    }

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws CaMgmtException {
        return client.addCertprofile(dbEntry);
    }

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CaMgmtException {
        return client.addCmpResponder(dbEntry);
    }

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws CaMgmtException {
        return client.removeCmpResponder(name);
    }

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws CaMgmtException {
        return client.changeCmpResponder(name, type, conf, base64Cert);
    }

    @Override
    public CmpResponderEntry getCmpResponder(
            final String name) {
        return client.getCmpResponder(name);
    }

    @Override
    public boolean addCrlSigner(
            final X509CrlSignerEntry dbEntry)
    throws CaMgmtException {
        return client.addCrlSigner(dbEntry);
    }

    @Override
    public boolean removeCrlSigner(
            final String crlSignerName)
    throws CaMgmtException {
        return client.removeCrlSigner(crlSignerName);
    }

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws CaMgmtException {
        return client.changeCrlSigner(dbEntry);
    }

    @Override
    public X509CrlSignerEntry getCrlSigner(
            final String name) {
        return client.getCrlSigner(name);
    }

    @Override
    public boolean addPublisher(
            final PublisherEntry dbEntry)
    throws CaMgmtException {
        return client.addPublisher(dbEntry);
    }

    @Override
    public List<PublisherEntry> getPublishersForCa(
            final String caName) {
        return client.getPublishersForCa(caName);
    }

    @Override
    public PublisherEntry getPublisher(
            final String publisherName) {
        return client.getPublisher(publisherName);
    }

    @Override
    public boolean removePublisher(
            final String publisherName)
    throws CaMgmtException {
        return client.removePublisher(publisherName);
    }

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws CaMgmtException {
        return client.changePublisher(name, type, conf);
    }

    @Override
    public CmpControlEntry getCmpControl(
            final String name) {
        return client.getCmpControl(name);
    }

    @Override
    public boolean addCmpControl(
            final CmpControlEntry dbEntry)
    throws CaMgmtException {
        return client.addCmpControl(dbEntry);
    }

    @Override
    public boolean removeCmpControl(
            final String name)
    throws CaMgmtException {
        return client.removeCmpControl(name);
    }

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws CaMgmtException {
        return client.changeCmpControl(name, conf);
    }

    @Override
    public Set<String> getEnvParamNames() {
        return client.getEnvParamNames();
    }

    @Override
    public String getEnvParam(
            final String name) {
        return client.getEnvParam(name);
    }

    @Override
    public boolean addEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        return client.addEnvParam(name, value);
    }

    @Override
    public boolean removeEnvParam(
            final String envParamName)
    throws CaMgmtException {
        return client.removeEnvParam(envParamName);
    }

    @Override
    public boolean changeEnvParam(
            final String name,
            final String value)
    throws CaMgmtException {
        return client.changeEnvParam(name, value);
    }

    @Override
    public boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws CaMgmtException {
        return client.revokeCa(caName, revocationInfo);
    }

    @Override
    public boolean unrevokeCa(
            final String caName)
    throws CaMgmtException {
        return client.unrevokeCa(caName);
    }

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CrlReason reason,
            final Date invalidityTime)
    throws CaMgmtException {
        return client.revokeCertificate(caName, serialNumber, reason, invalidityTime);
    }

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CaMgmtException {
        return client.unrevokeCertificate(caName, serialNumber);
    }

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CaMgmtException {
        return client.removeCertificate(caName, serialNumber);
    }

    @Override
    public X509Certificate generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws CaMgmtException {
        return client.generateCertificate(caName, profileName, user,
                encodedPkcs10Request);
    }

    @Override
    public X509Certificate generateRootCa(
            final X509CaEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws CaMgmtException {
        return client.generateRootCa(caEntry, certprofileName, p10Req);
    }

    @Override
    public boolean addUser(
            final AddUserEntry userEntry)
    throws CaMgmtException {
        return client.addUser(userEntry);
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws CaMgmtException {
        return client.changeUser(username, password, cnRegex);
    }

    @Override
    public boolean removeUser(
            final String username)
    throws CaMgmtException {
        return client.removeUser(username);
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws CaMgmtException {
        return client.getUser(username);
    }

    @Override
    public X509CRL generateCrlOnDemand(
            final String caName)
    throws CaMgmtException {
        return client.generateCrlOnDemand(caName);
    }

    @Override
    public X509CRL getCrl(
            final String caName,
            final BigInteger crlNumber)
    throws CaMgmtException {
        return client.getCrl(caName, crlNumber);
    }

    @Override
    public X509CRL getCurrentCrl(
            final String caName)
    throws CaMgmtException {
        return client.getCurrentCrl(caName);
    }

    @Override
    public boolean addScep(
            final ScepEntry scepEntry)
    throws CaMgmtException {
        return client.addScep(scepEntry);
    }

    @Override
    public boolean removeScep(
            final String name)
    throws CaMgmtException {
        return client.removeScep(name);
    }

    @Override
    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws CaMgmtException {
        return client.changeScep(scepEntry);
    }

    @Override
    public Set<String> getScepNames() {
        return client.getScepNames();
    }

    @Override
    public ScepEntry getScepEntry(
            final String name)
    throws CaMgmtException {
        return client.getScepEntry(name);
    }

    /*
    public static void main(
            final String[] args) {
        try {
            CaManagerClient c = new CaManagerClient();
            c.setServerURL("http://localhost:8080/pkiconsole/hessian");
            c.init();
            X509CrlSignerEntry crlSigner = c.getCrlSigner("CASIGN.CRLSIGNER");
            System.out.println(crlSigner);

            CAEntry caEntry = c.getCa("RCA1");
            System.out.println(caEntry);
        } catch (Exception ex) {
            e.printStackTrace();
        }
    } */

}
