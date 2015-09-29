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

package org.xipki.pki.ca.server.mgmt.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.rmi.UnexpectedException;
import java.util.Properties;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.pki.ca.server.mgmt.api.CAEntry;
import org.xipki.pki.ca.server.mgmt.api.CertArt;
import org.xipki.pki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.security.api.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "ca-export",
        description = "export CA configuration")
public class CaExportCmd extends CaCmd
{
    static final String KEY_ART = "ART";

    static final String KEY_NEXT_SN = "NEXT_SN";

    static final String KEY_NEXT_CRLNO = "NEXT_CRLNO";

    static final String KEY_STATUS = "STATUS";

    static final String KEY_CACERT_URIS = "CACERT_URIS";

    static final String KEY_CRL_URIS = "CRL_URIS";

    static final String KEY_DELTACRL_URIS = "DELTACRL_URIS";

    static final String KEY_OCSP_URIS = "OCSP_URIS";

    static final String KEY_MAX_VALIDITY = "MAX_VALIDITY";

    static final String KEY_CRLSIGNER_NAME = "CRLSIGNER_NAME";

    static final String KEY_CMPCONTROL_NAME = "CMPCONTROL_NAME";

    static final String KEY_DUPLICATE_KEY = "DUPLICATE_KEY";

    static final String KEY_DUPLICATE_SUBJECT = "DUPLICATE_SUBJECT";

    static final String KEY_VALIDITY_MODE = "VALIDITY_MODE";

    static final String KEY_PERMISSIONS = "PERMISSIONS";

    static final String KEY_NUM_CRLS = "NUM_CRLS";

    static final String KEY_EXPIRATION_PERIOD = "EXPIRATION_PERIOD";

    static final String KEY_KEEP_EXPIRED_CERT_DAYS = "KEEP_EXPIRED_CERT_DAYS";

    static final String KEY_REVOKED = "REVOKED";

    static final String KEY_REV_REASON = "RR";

    static final String KEY_REV_TIME = "RT";

    static final String KEY_REV_INV_TIME = "RIT";

    static final String KEY_SIGNER_TYPE = "SIGNER_TYPE";

    static final String KEY_SIGNER_CONF = "SIGNER_CONF";

    static final String KEY_CERT = "CERT";

    static final String KEY_EXTRA_CONTROL = "EXTRA_CONTROL";

    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String name;

    @Option(name = "--out", aliases = "-o",
            required = true,
            description = "where to save the CA configuration\n"
                    + "(required)")
    private String confFile;

    @Override
    protected Object _doExecute()
    throws Exception
    {
        CAEntry _entry = caManager.getCA(name);
        if (_entry == null)
        {
            throw new UnexpectedException("no CA named " + name + " is defined");
        }

        if (!(_entry instanceof X509CAEntry))
        {
            throw new UnexpectedException(
                    "unsupported CAEntry type " + _entry.getClass().getName());
        }

        X509CAEntry entry = (X509CAEntry) _entry;

        Properties props = new Properties();

        // ART
        propsput(props, KEY_ART, CertArt.X509PKC.name());

        // NEXT_SN
        propsput(props, KEY_NEXT_SN, entry.getNextSerial());

        // NEXT_CRLNO
        propsput(props, KEY_NEXT_CRLNO, entry.getNextCRLNumber());

        // STATUS
        propsput(props, KEY_STATUS, entry.getStatus().name());

        // CACERT_URIS
        propsput(props, KEY_CACERT_URIS, entry.getCacertUris());

        // CRL_URIS
        propsput(props, KEY_CRL_URIS, entry.getCrlUrisAsString());

        // DELTACRL_URIS
        propsput(props, KEY_DELTACRL_URIS, entry.getDeltaCrlUrisAsString());

        // OCSP_URIS
        propsput(props, KEY_OCSP_URIS, entry.getOcspUrisAsString());

        // MAX_VALIDITY
        propsput(props, KEY_MAX_VALIDITY, entry.getMaxValidity());

        // CRLSIGNER_NAME
        propsput(props, KEY_CRLSIGNER_NAME, entry.getCrlSignerName());

        // CMPCONTROL_NAME
        propsput(props, KEY_CMPCONTROL_NAME, entry.getCmpControlName());

        // DUPLICATE_KEY
        propsput(props, KEY_DUPLICATE_KEY, entry.getDuplicateKeyMode().name());

        // DUPLICATE_SUBJECT
        propsput(props, KEY_DUPLICATE_SUBJECT, entry.getDuplicateSubjectMode().name());

        // VALIDITY_MODE
        propsput(props, KEY_VALIDITY_MODE, entry.getValidityMode().name());

        // PERMISSIONS
        propsput(props, KEY_PERMISSIONS, entry.getPermissionsAsText());

        // NUM_CRLS
        propsput(props, KEY_NUM_CRLS, entry.getNumCrls());

        // EXPIRATION_PERIOD
        propsput(props, KEY_EXPIRATION_PERIOD, entry.getExpirationPeriod());

        // KEEP_EXPIRED_CERT_DAYS
        propsput(props, KEY_KEEP_EXPIRED_CERT_DAYS, entry.getKeepExpiredCertInDays());

        // REVOKED
        CertRevocationInfo revInfo = entry.getRevocationInfo();
        propsput(props, KEY_REVOKED, revInfo != null);
        if (revInfo != null)
        {
            if (revInfo.getReason() != null)
            {
                propsput(props, KEY_REV_REASON, revInfo.getReason().getCode());
            }

            if (revInfo.getRevocationTime() != null)
            {
                propsput(props, KEY_REV_TIME, revInfo.getRevocationTime().getTime() / 1000);
            }

            if (revInfo.getInvalidityTime() != null)
            {
                propsput(props, KEY_REV_INV_TIME, revInfo.getInvalidityTime().getTime() / 1000);
            }
        }

        // SIGNER_TYPE
        propsput(props, KEY_SIGNER_TYPE, entry.getSignerType());

        // SIGNER_CONF
        propsput(props, KEY_SIGNER_CONF, entry.getSignerConf());

        // CERT
        byte[] bytes = entry.getCertificate().getEncoded();
        propsput(props, KEY_CERT, IoUtil.base64Encode(bytes, false));

        // EXTRA_CONTROL
        propsput(props, KEY_EXTRA_CONTROL, entry.getExtraControl());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        props.store(out, "CA configuration");
        saveVerbose("saved CA configuration to", new File(confFile), out.toByteArray());
        return null;
    }

    private static void propsput(
            final Properties props,
            final String key,
            final Object value)
    {
        if (value instanceof String)
        {
            props.put(key, (String) value);
        } else if (value != null)
        {
            props.put(key, value.toString());
        }
    }

}
