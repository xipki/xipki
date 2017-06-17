/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.pki.ocsp.server.impl.store.crl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditStatus;
import org.xipki.audit.PciAuditEvent;
import org.xipki.common.util.DateUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.pki.ocsp.api.OcspStoreException;
import org.xipki.pki.ocsp.server.impl.store.db.DbCertStatusStore;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgoType;
import org.xipki.security.util.X509Util;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class CrlDbCertStatusStore extends DbCertStatusStore {

    public static final String KEY_CA_REVOCATION_TIME = "ca.revocation.time";

    public static final String KEY_CA_INVALIDITY_TIME = "ca.invalidity.time";

    private class CrlUpdateService implements Runnable {

        @Override
        public void run() {
            try {
                initializeStore(datasource);
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "error while calling initializeStore() for store " + name);
            }
        }

    } // StoreUpdateService

    private static final Logger LOG = LoggerFactory.getLogger(CrlDbCertStatusStore.class);

    private final AtomicBoolean crlUpdateInProcess = new AtomicBoolean(false);

    private X509Certificate caCert;

    private X509Certificate issuerCert;

    private String crlFilename;

    private String crlUrl;

    private String certsDirName;

    private boolean useUpdateDatesFromCrl;

    private boolean crlUpdated;

    private boolean crlUpdateFailed;

    @Override
    public void init(final String conf, final DataSourceWrapper datasource,
            final Set<HashAlgoType> certHashAlgos) throws OcspStoreException {
        ParamUtil.requireNonBlank("conf", conf);
        this.datasource = ParamUtil.requireNonNull("datasource", datasource);

        StoreConf storeConf = new StoreConf(conf);
        this.crlFilename = IoUtil.expandFilepath(storeConf.crlFile());
        this.crlUrl = storeConf.crlUrl();
        this.certsDirName = (storeConf.certsDir() == null) ? null
                : IoUtil.expandFilepath(storeConf.certsDir());
        this.caCert = parseCert(storeConf.caCertFile());
        if (storeConf.issuerCertFile() != null) {
            this.issuerCert = parseCert(storeConf.issuerCertFile());
        } else {
            this.issuerCert = null;
        }
        this.useUpdateDatesFromCrl = storeConf.isUseUpdateDatesFromCrl();

        initializeStore(datasource);

        super.init(conf, datasource, certHashAlgos);
    }

    @Override
    protected List<Runnable> getScheduledServices() {
        return Arrays.asList(new CrlUpdateService());
    }

    @Override
    protected boolean isInitialized() {
        return crlUpdated && super.isInitialized();
    }

    @Override
    protected boolean isInitializationFailed() {
        return crlUpdateFailed || super.isInitializationFailed();
    }

    private static X509Certificate parseCert(final String certFile) throws OcspStoreException {
        try {
            return X509Util.parseCert(certFile);
        } catch (CertificateException | IOException ex) {
            throw new OcspStoreException("could not parse X.509 certificate from file "
                    + certFile + ": " + ex.getMessage(), ex);
        }
    }

    private synchronized void initializeStore(DataSourceWrapper datasource) {
        if (crlUpdateInProcess.get()) {
            return;
        }

        crlUpdateInProcess.set(true);

        Boolean updateCrlSuccessful = null;
        File updateMeFile = new File(crlFilename + ".UPDATEME");
        if (!updateMeFile.exists()) {
            LOG.info("The CRL will not be updated. Create new file {} to force the update",
                    updateMeFile.getAbsolutePath());
            crlUpdated = true;
            crlUpdateFailed = false;
            return;
        }

        try {

            File fullCrlFile = new File(crlFilename);
            if (!fullCrlFile.exists()) {
                // file does not exist
                LOG.warn("CRL File {} does not exist", crlFilename);
                return;
            }

            auditPciEvent(AuditLevel.INFO, "UPDATE_CERTSTORE", "a newer CRL is available");
            updateCrlSuccessful = false;

            X509CRL crl = X509Util.parseCrl(crlFilename);

            File revFile = new File(crlFilename + ".revocation");
            CertRevocationInfo caRevInfo = null;
            if (revFile.exists()) {
                Properties props = new Properties();
                FileInputStream is = new FileInputStream(revFile);
                try {
                    props.load(is);
                } finally {
                    is.close();
                }

                String str = props.getProperty(KEY_CA_REVOCATION_TIME);
                if (StringUtil.isNotBlank(str)) {
                    Date revocationTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                    Date invalidityTime = null;

                    str = props.getProperty(KEY_CA_INVALIDITY_TIME);
                    if (StringUtil.isNotBlank(str)) {
                        invalidityTime = DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
                    }
                    caRevInfo = new CertRevocationInfo(CrlReason.UNSPECIFIED,
                            revocationTime, invalidityTime);
                }
            }

            ImportCrl importCrl = new ImportCrl(datasource, useUpdateDatesFromCrl, crl, crlUrl,
                    caCert, issuerCert, caRevInfo, certsDirName);
            updateCrlSuccessful = importCrl.importCrlToOcspDb();
            crlUpdated = true;
            if (updateCrlSuccessful) {
                crlUpdateFailed = false;
                LOG.info("updated CertStore {} successfully", name);
            } else {
                crlUpdateFailed = true;
                LOG.error("updating CertStore {} failed", name);
            }
        } catch (Throwable th) {
            LogUtil.error(LOG, th, "could not execute initializeStore()");
            crlUpdateFailed = true;
            crlUpdated = true;
        } finally {
            updateMeFile.delete();
            crlUpdateInProcess.set(false);
            if (updateCrlSuccessful != null) {
                AuditLevel auditLevel = updateCrlSuccessful ? AuditLevel.INFO : AuditLevel.ERROR;
                AuditStatus auditStatus = updateCrlSuccessful ? AuditStatus.SUCCESSFUL
                        : AuditStatus.FAILED;
                auditPciEvent(auditLevel, "UPDATE_CRL", auditStatus.name());
            }
        }
    } // method initializeStore

    private void auditPciEvent(final AuditLevel auditLevel, final String eventType,
            final String auditStatus) {
        PciAuditEvent event = new PciAuditEvent(new Date());
        event.setUserId("SYSTEM");
        event.setEventType(eventType);
        event.setAffectedResource("CRL-Updater");
        event.setStatus(auditStatus);
        event.setLevel(auditLevel);
        auditService().logEvent(event);
    }

}
