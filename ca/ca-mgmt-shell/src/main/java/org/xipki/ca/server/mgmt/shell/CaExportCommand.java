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

package org.xipki.ca.server.mgmt.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.rmi.UnexpectedException;
import java.util.Properties;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CertArt;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.security.api.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "ca-export", description="export CA configuration")
public class CaExportCommand extends CaCommand
{
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
        if(_entry == null)
        {
            throw new UnexpectedException("no CA named " + name + " is defined");
        }

        if(_entry instanceof X509CAEntry == false)
        {
            throw new UnexpectedException("unsupported CAEntry type " + _entry.getClass().getName());
        }

        X509CAEntry entry = (X509CAEntry) _entry;

        Properties props = new Properties();

        // ART
        propsput(props, "ART", CertArt.X509PKC.name());

        // NEXT_SERIAL
        propsput(props, "NEXT_SERIAL", entry.getNextSerial());

        // NEXT_CRLNO
        propsput(props, "NEXT_CRLNO", entry.getNextCRLNumber());

        // STATUS
        propsput(props, "STATUS", entry.getStatus().name());

        // CRL_URIS
        propsput(props, "CRL_URIS", entry.getCrlUrisAsString());

        // DELTACRL_URIS
        propsput(props, "DELTACRL_URIS", entry.getDeltaCrlUrisAsString());

        // OCSP_URIS
        propsput(props, "OCSP_URIS", entry.getOcspUrisAsString());

        // MAX_VALIDITY
        propsput(props, "MAX_VALIDITY", entry.getMaxValidity());

        // CRLSIGNER_NAME
        propsput(props, "CRLSIGNER_NAME", entry.getCrlSignerName());

        // CMPCONTROL_NAME
        propsput(props, "CMPCONTROL_NAME", entry.getCmpControlName());

        // DUPLICATE_KEY
        propsput(props, "DUPLICATE_KEY", entry.getDuplicateKeyMode().name());

        // DUPLICATE_SUBJECT
        propsput(props, "DUPLICATE_SUBJECT", entry.getDuplicateSubjectMode().name());

        // VALIDITY_MODE
        propsput(props, "VALIDITY_MODE", entry.getValidityMode().name());

        // PERMISSIONS
        propsput(props, "PERMISSIONS", entry.getPermissionsAsText());

        // NUM_CRLS
        propsput(props, "NUM_CRLS", entry.getNumCrls());

        // EXPIRATION_PERIOD
        propsput(props, "EXPIRATION_PERIOD", entry.getExpirationPeriod());

        // REVOKED
        CertRevocationInfo revInfo = entry.getRevocationInfo();
        propsput(props, "REVOKED", revInfo != null);
        if(revInfo != null)
        {
            if(revInfo.getReason() != null)
            {
                propsput(props, "REV_REASON", revInfo.getReason().getCode());
            }

            if(revInfo.getRevocationTime() != null)
            {
                propsput(props, "REV_TIME", revInfo.getRevocationTime().getTime() / 1000);
            }

            if(revInfo.getInvalidityTime() != null)
            {
                propsput(props, "REV_INV_TIME", revInfo.getInvalidityTime().getTime() / 1000);
            }
        }

        // SIGNER_TYPE
        propsput(props, "SIGNER_TYPE", entry.getSignerType());

        // SIGNER_CONF
        propsput(props, "SIGNER_CONF", entry.getSignerConf());

        // CERT
        byte[] bytes = entry.getCertificate().getEncoded();
        propsput(props, "CERT", IoUtil.base64Encode(bytes, false));

        // EXTRA_CONTROL
        propsput(props, "EXTRA_CONTROL", entry.getExtraControl());

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
        if(value instanceof String)
        {
            props.put(key, (String) value);
        }
        else if(value != null)
        {
            props.put(key, value.toString());
        }
    }

}
