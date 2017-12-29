/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.server.impl.store.crl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

import org.xipki.common.util.StringUtil;
import org.xipki.ocsp.api.OcspStoreException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class StoreConf {

    /*
     * required
     */
    private static final String KEY_crl_file = "crl.file";

    /*
     * optional
     */
    private static final String KEY_crl_url = "crl.url";

    /*
     * Whether thisUpdate and nextUpdate of CRL are used in the corresponding fields
     * of OCSP response. The default value is true.
     *
     * optional
     */
    private static final String KEY_useUpdateDatesFromCrl = "useUpdateDatesFromCrl";

    /*
     * required
     */
    private static final String KEY_caCert_file = "caCert.file";

    /*
     * required for indirect CRL
     */
    private static final String KEY_issuerCert_file = "issuerCert.file";

    /*
     * Folder containing the DER-encoded certificates suffixed with ".der" and ".crt"
     * optional.
     */
    private static final String KEY_certs_dir = "certs.dir";

    private String crlFile;

    /*
     * optional, can be null
     */
    private String crlUrl;

    private boolean useUpdateDatesFromCrl = true;

    private String caCertFile;

    /*
     * optional, can be null, but required for indirect CRL
     */
    private String issuerCertFile;

    /*
     * optional, can be null
     */
    private String certsDir;

    StoreConf(String propsConf) throws OcspStoreException {
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(propsConf.getBytes()));
        } catch (IOException ex) {
            throw new OcspStoreException("could not load properties: " + ex.getMessage(), ex);
        }

        this.crlFile = getRequiredProperty(props, KEY_crl_file);
        this.crlUrl = getOptionalProperty(props, KEY_crl_url);
        this.caCertFile = getRequiredProperty(props, KEY_caCert_file);
        this.issuerCertFile = getOptionalProperty(props, KEY_issuerCert_file);
        this.certsDir = getOptionalProperty(props, KEY_certs_dir);

        String propKey = KEY_useUpdateDatesFromCrl;
        String propValue = props.getProperty(propKey);
        if (propValue != null) {
            propValue = propValue.trim();
            if ("true".equalsIgnoreCase(propValue)) {
                this.useUpdateDatesFromCrl = true;
            } else if ("false".equalsIgnoreCase(propValue)) {
                this.useUpdateDatesFromCrl = false;
            } else {
                throw new OcspStoreException("invalid property " + propKey + ": '"
                        + propValue + "'");
            }
        } else {
            this.useUpdateDatesFromCrl = true;
        }
    }

    String crlFile() {
        return crlFile;
    }

    String crlUrl() {
        return crlUrl;
    }

    boolean isUseUpdateDatesFromCrl() {
        return useUpdateDatesFromCrl;
    }

    String caCertFile() {
        return caCertFile;
    }

    String issuerCertFile() {
        return issuerCertFile;
    }

    String certsDir() {
        return certsDir;
    }

    private String getRequiredProperty(Properties props, String propKey)
            throws OcspStoreException {
        String str = props.getProperty(propKey);
        if (str == null) {
            throw new OcspStoreException("missing required property " + propKey);
        }
        String ret = str.trim();
        if (StringUtil.isBlank(ret)) {
            throw new OcspStoreException("property " + propKey + " must not be blank");
        }
        return str.trim();
    }

    private String getOptionalProperty(Properties props, String propKey) throws OcspStoreException {
        String str = props.getProperty(propKey);
        if (str == null) {
            return null;
        }
        return str.trim();
    }

}
