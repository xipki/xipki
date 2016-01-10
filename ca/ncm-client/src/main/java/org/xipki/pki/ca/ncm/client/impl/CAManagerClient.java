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

package org.xipki.pki.ca.ncm.client.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.util.X509Util;

import com.caucho.hessian.client.HessianProxyFactory;

/**
 * @author Lijun Liao
 */

public class CAManagerClient implements CAManager {

    private final Logger LOG = LoggerFactory.getLogger(getClass());

    private HessianCAManager client;

    private int version;

    private String serverURL;

    public CAManagerClient() {
    }

    public void init()
    throws Exception {
        if (serverURL == null) {
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
    throws Exception {
    }

    public void setServerURL(
            final String serverURL) {
        this.serverURL = serverURL;
    }

    private void determineServerVersion() {
        String versionS = client.getAttribute("version");
        if (versionS == null) {
            version = 0;
        } else {
            try {
                version = Integer.parseInt(versionS);
            } catch (NumberFormatException e) {
                LOG.info("invalid version {}, reset it to 0", versionS);
            }
        }
        LOG.info("set version to {}", version);
    }

    @Override
    public CASystemStatus getCASystemStatus() {
        return client.getCASystemStatus();
    }

    @Override
    public boolean unlockCA() {
        return client.unlockCA();
    }

    @Override
    public boolean publishRootCA(
            final String caName,
            final String certprofile)
    throws CAMgmtException {
        return client.publishRootCA(caName, certprofile);
    }

    @Override
    public boolean republishCertificates(
            final String caName,
            final List<String> publisherNames)
    throws CAMgmtException {
        return client.republishCertificates(caName, publisherNames);
    }

    @Override
    public boolean clearPublishQueue(
            final String caName,
            final List<String> publisherNames)
    throws CAMgmtException {
        return client.clearPublishQueue(caName, publisherNames);
    }

    @Override
    public boolean removeCA(
            final String caName)
    throws CAMgmtException {
        return client.removeCA(caName);
    }

    @Override
    public boolean restartCaSystem() {
        return client.restartCaSystem();
    }

    @Override
    public boolean notifyCAChange()
    throws HessianCAMgmtException {
        return client.notifyCAChange();
    }

    @Override
    public boolean addCaAlias(
            final String aliasName,
            final String caName)
    throws CAMgmtException {
        return client.addCaAlias(aliasName, caName);
    }

    @Override
    public boolean removeCaAlias(
            final String aliasName)
    throws CAMgmtException {
        return client.removeCaAlias(aliasName);
    }

    @Override
    public Set<String> getAliasesForCA(
            final String caName) {
        return client.getAliasesForCA(caName);
    }

    @Override
    public String getCaNameForAlias(
            final String aliasName) {
        return client.getCaName(aliasName);
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
    public boolean addCA(
            final CAEntry newCaDbEntry)
    throws CAMgmtException {
        return client.addCA(newCaDbEntry);
    }

    @Override
    public CAEntry getCA(
            final String caName) {
        return client.getCA(caName);
    }

    @Override
    public boolean changeCA(
            final ChangeCAEntry changeCAentry)
    throws CAMgmtException {
        return client.changeCA(changeCAentry);
    }

    @Override
    public boolean removeCertprofileFromCA(
            final String profileName,
            final String caName)
    throws CAMgmtException {
        return client.removeCertprofileFromCA(profileName, caName);
    }

    @Override
    public boolean addCertprofileToCA(
            final String profileName,
            final String profileLocalname,
            final String caName)
    throws CAMgmtException {
        return client.addCertprofileToCA(profileName, profileLocalname, caName);
    }

    @Override
    public boolean removePublisherFromCA(
            final String publisherName,
            final String caName)
    throws CAMgmtException {
        return client.removePublisherFromCA(publisherName, caName);
    }

    @Override
    public boolean addPublisherToCA(
            final String publisherName,
            final String caName)
    throws CAMgmtException {
        return client.addPublisherToCA(publisherName, caName);
    }

    @Override
    public Map<String, String> getCertprofilesForCA(
            final String caName) {
        return client.getCertprofilesForCA(caName);
    }

    @Override
    public Set<CAHasRequestorEntry> getCmpRequestorsForCA(
            final String caName) {
        return client.getCmpRequestorsForCA(caName);
    }

    @Override
    public CmpRequestorEntry getCmpRequestor(
            final String name) {
        return client.getCmpRequestor(name);
    }

    @Override
    public boolean addCmpRequestor(
            final CmpRequestorEntry dbEntry)
    throws CAMgmtException {
        return client.addCmpRequestor(dbEntry);
    }

    @Override
    public boolean removeCmpRequestor(
            final String requestorName)
    throws CAMgmtException {
        return client.removeCmpRequestor(requestorName);
    }

    @Override
    public boolean changeCmpRequestor(
            final String name,
            final String base64Cert)
    throws CAMgmtException {
        return client.changeCmpRequestor(name, base64Cert);
    }

    @Override
    public boolean removeCmpRequestorFromCA(
            final String requestorName,
            final String caName)
    throws CAMgmtException {
        return client.removeCmpRequestorFromCA(requestorName, caName);
    }

    @Override
    public boolean addCmpRequestorToCA(
            final CAHasRequestorEntry requestor,
            final String caName)
    throws CAMgmtException {
        return client.addCmpRequestorToCA(requestor, caName);
    }

    @Override
    public CertprofileEntry getCertprofile(
            final String profileName) {
        return client.getCertprofile(profileName);
    }

    @Override
    public boolean removeCertprofile(
            final String profileName)
    throws CAMgmtException {
        return client.removeCertprofile(profileName);
    }

    @Override
    public boolean changeCertprofile(
            final String name,
            final String type,
            final String conf)
    throws CAMgmtException {
        return client.changeCertprofile(name, type, conf);
    }

    @Override
    public boolean addCertprofile(
            final CertprofileEntry dbEntry)
    throws CAMgmtException {
        return client.addCertprofile(dbEntry);
    }

    @Override
    public boolean addCmpResponder(
            final CmpResponderEntry dbEntry)
    throws CAMgmtException {
        return client.addCmpResponder(dbEntry);
    }

    @Override
    public boolean removeCmpResponder(
            final String name)
    throws CAMgmtException {
        return client.removeCmpResponder(name);
    }

    @Override
    public boolean changeCmpResponder(
            final String name,
            final String type,
            final String conf,
            final String base64Cert)
    throws CAMgmtException {
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
    throws CAMgmtException {
        return client.addCrlSigner(dbEntry);
    }

    @Override
    public boolean removeCrlSigner(
            final String crlSignerName)
    throws CAMgmtException {
        return client.removeCrlSigner(crlSignerName);
    }

    @Override
    public boolean changeCrlSigner(
            final X509ChangeCrlSignerEntry dbEntry)
    throws CAMgmtException {
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
    throws CAMgmtException {
        return client.addPublisher(dbEntry);
    }

    @Override
    public List<PublisherEntry> getPublishersForCA(
            final String caName) {
        return client.getPublishersForCA(caName);
    }

    @Override
    public PublisherEntry getPublisher(
            final String publisherName) {
        return client.getPublisher(publisherName);
    }

    @Override
    public boolean removePublisher(
            final String publisherName)
    throws CAMgmtException {
        return client.removePublisher(publisherName);
    }

    @Override
    public boolean changePublisher(
            final String name,
            final String type,
            final String conf)
    throws CAMgmtException {
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
    throws CAMgmtException {
        return client.addCmpControl(dbEntry);
    }

    @Override
    public boolean removeCmpControl(
            final String name)
    throws CAMgmtException {
        return client.removeCmpControl(name);
    }

    @Override
    public boolean changeCmpControl(
            final String name,
            final String conf)
    throws CAMgmtException {
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
    throws CAMgmtException {
        return client.addEnvParam(name, value);
    }

    @Override
    public boolean removeEnvParam(
            final String envParamName)
    throws CAMgmtException {
        return client.removeEnvParam(envParamName);
    }

    @Override
    public boolean changeEnvParam(
            final String name,
            final String value)
    throws CAMgmtException {
        return client.changeEnvParam(name, value);
    }

    @Override
    public boolean revokeCa(
            final String caName,
            final CertRevocationInfo revocationInfo)
    throws CAMgmtException {
        return client.revokeCa(caName, revocationInfo);
    }

    @Override
    public boolean unrevokeCa(
            final String caName)
    throws CAMgmtException {
        return client.unrevokeCa(caName);
    }

    @Override
    public boolean revokeCertificate(
            final String caName,
            final BigInteger serialNumber,
            final CRLReason reason,
            final Date invalidityTime)
    throws CAMgmtException {
        return client.revokeCertificate(caName, serialNumber, reason, invalidityTime);
    }

    @Override
    public boolean unrevokeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CAMgmtException {
        return client.unrevokeCertificate(caName, serialNumber);
    }

    @Override
    public boolean removeCertificate(
            final String caName,
            final BigInteger serialNumber)
    throws CAMgmtException {
        return client.removeCertificate(caName, serialNumber);
    }

    @Override
    public X509Certificate generateCertificate(
            final String caName,
            final String profileName,
            final String user,
            final byte[] encodedPkcs10Request)
    throws CAMgmtException {
        byte[] encodedCert = client.generateCertificate(caName, profileName, user,
                encodedPkcs10Request);
        try {
            return X509Util.parseCert(encodedCert);
        } catch (CertificateException | IOException e) {
            throw new CAMgmtException("could not parse the certificate: " + e.getMessage(), e);
        }
    }

    @Override
    public X509Certificate generateRootCA(
            final X509CAEntry caEntry,
            final String certprofileName,
            final byte[] p10Req)
    throws CAMgmtException {
        return client.generateSelfSignedCA(caEntry, certprofileName, p10Req);
    }

    @Override
    public boolean addUser(
            final AddUserEntry userEntry)
    throws CAMgmtException {
        return client.addUser(userEntry);
    }

    @Override
    public boolean changeUser(
            final String username,
            final String password,
            final String cnRegex)
    throws CAMgmtException {
        return client.changeUser(username, password, cnRegex);
    }

    @Override
    public boolean removeUser(
            final String username)
    throws CAMgmtException {
        return client.removeUser(username);
    }

    @Override
    public UserEntry getUser(
            final String username)
    throws CAMgmtException {
        return client.getUser(username);
    }

    @Override
    public boolean addScep(
            final ScepEntry scepEntry)
    throws CAMgmtException {
        return client.addScep(scepEntry);
    }

    @Override
    public boolean removeScep(
            final String name)
    throws CAMgmtException {
        return client.removeScep(name);
    }

    @Override
    public boolean changeScep(
            final ChangeScepEntry scepEntry)
    throws CAMgmtException {
        return client.changeScep(scepEntry);
    }

    @Override
    public Set<String> getScepNames() {
        return client.getScepNames();
    }

    @Override
    public ScepEntry getScepEntry(
            final String name)
    throws CAMgmtException {
        return client.getScepEntry(name);
    }

    public static void main(
            final String[] args) {
        try {
            CAManagerClient c = new CAManagerClient();
            c.setServerURL("http://localhost:8080/pkiconsole/hessian");
            c.init();
            X509CrlSignerEntry crlSigner = c.getCrlSigner("CASIGN.CRLSIGNER");
            System.out.println(crlSigner);

            CAEntry caEntry = c.getCA("RCA1");
            System.out.println(caEntry);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
