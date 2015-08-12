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

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.apache.karaf.shell.commands.Option;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.CertArt;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.password.api.PasswordResolver;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.util.X509Util;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-ca", name = "ca-addf", description="add CA from configuration file")
public class CaAddFromFileCommand extends CaCommand
{
    @Option(name = "--name", aliases = "-n",
            required = true,
            description = "CA name\n"
                    + "(required)")
    private String caName;

    @Option(name = "--conf-file",
            required = true,
            description = "CA configuration file\n"
                    + "(required)")
    private String confFile;

    private PasswordResolver passwordResolver;

    public void setPasswordResolver(
            final PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    @Override
    protected Object _doExecute()
    throws Exception
    {
        X509CAEntry caEntry = getCAEntry(false);

        boolean b = caManager.addCA(caEntry);
        output(b, "added", "could not add", "CA " + caEntry.getName());
        return null;
    }

    protected X509CAEntry getCAEntry(
            final boolean ignoreCert)
    throws Exception
    {
        Properties props = new Properties();
        confFile = IoUtil.expandFilepath(confFile);
        FileInputStream stream = new FileInputStream(confFile);
        try
        {
            props.load(stream);
        }finally
        {
            stream.close();
        }

        // ART
        String key = "ART";
        String s = getStrProp(props, key, true);
        CertArt art = CertArt.valueOf(s);
        assertNotNull(art, key, s);

        if(art != CertArt.X509PKC)
        {
            throw new IllegalCmdParamException("unsupported " + key + ": '" + s + "'");
        }

        // NEXT_SERIAL
        key = "NEXT_SERIAL";
        long nextSerial = getRequiredLongProp(props, key);
        if(nextSerial < 0)
        {
            throw new IllegalCmdParamException("invalid " + key + ": " + nextSerial);
        }

        // NEXT_CRLNO
        key = "NEXT_CRLNO";
        int nextCrlNumber = getRequiredIntProp(props, key);
        if(nextCrlNumber < 1)
        {
            throw new IllegalCmdParamException("invalid " + key + ": " + nextCrlNumber);
        }

        // NUM_CRLS
        key = "NUM_CRLS";
        int numCrls = getRequiredIntProp(props, key);
        if(numCrls < 0)
        {
            throw new IllegalCmdParamException("invalid " + key + ": " + numCrls);
        }

        // EXPIRATION_PERIOD
        key = "EXPIRATION_PERIOD";
        int expirationPeriod = getRequiredIntProp(props, key);
        if(expirationPeriod < 0)
        {
            throw new IllegalCmdParamException("invalid " + key + ": " + expirationPeriod);
        }

        // SIGNER_TYPE
        key = "SIGNER_TYPE";
        String signerType = getStrProp(props, key, true);

        // SIGNER_CONF
        key = "SIGNER_CONF";
        String signerConf = getStrProp(props, key, true);

        if("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType))
        {
            signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf,
                    passwordResolver);
        }

        // CRL_URIS
        key = "CRL_URIS";
        s = getStrProp(props, key, false);
        List<String> crlUris = null;
        if(s != null)
        {
            crlUris = StringUtil.split(s, ", ");
        }

        // DELTACRL_URIS
        key = "DELTACRL_URIS";
        s = getStrProp(props, key, false);
        List<String> deltaCrlUris = null;
        if(s != null)
        {
            deltaCrlUris = StringUtil.split(s, ", ");
        }

        // OCSP_URIS
        key = "OCSP_URIS";
        s = getStrProp(props, key, false);
        List<String> ocspUris = null;
        if(s != null)
        {
            ocspUris = StringUtil.split(s, ", ");
        }

        // CACERT_URIS
        key = "CACERT_URIS";
        s = getStrProp(props, key, false);
        List<String> caCertUris = null;
        if(s != null)
        {
            ocspUris = StringUtil.split(s, ", ");
        }

        X509CAEntry entry = new X509CAEntry(
                caName, nextSerial, nextCrlNumber, signerType, signerConf,
                caCertUris, ocspUris, crlUris, deltaCrlUris,
                numCrls, expirationPeriod);

        // STATUS
        key = "STATUS";
        s = getStrProp(props, key, true);
        CAStatus status = CAStatus.getCAStatus(s);
        assertNotNull(status, key, s);
        entry.setStatus(status);

        // DUPLICATE_KEY
        key = "DUPLICATE_KEY";
        s = getStrProp(props, key, true);
        DuplicationMode duplicateKey = DuplicationMode.valueOf(s);
        assertNotNull(duplicateKey, key, s);
        entry.setDuplicateKeyMode(duplicateKey);

        // DUPLICATE_SUBJECT
        key = "DUPLICATE_SUBJECT";
        s = getStrProp(props, key, true);
        DuplicationMode duplicateSubject = DuplicationMode.valueOf(s);
        assertNotNull(duplicateSubject, key, s);
        entry.setDuplicateSubjectMode(duplicateSubject);

        // VALIDITY_MODE
        key = "VALIDITY_MODE";
        s = getStrProp(props, key, true);
        ValidityMode validityMode = ValidityMode.valueOf(s);
        assertNotNull(validityMode, key, s);
        entry.setValidityMode(validityMode);

        // CRLSIGNER_NAME
        key = "CRLSIGNER_NAME";
        s = getStrProp(props, key, false);
        if(s != null)
        {
            entry.setCrlSignerName(s);
        }

        // CMPCONTROL_NAME
        key = "CMPCONTROL_NAME";
        s = getStrProp(props, key, false);
        if(s != null)
        {
            entry.setCmpControlName(s);
        }

        // MAX_VALIDITY
        key = "MAX_VALIDITY";
        s = getStrProp(props, key, true);
        CertValidity maxValidity = CertValidity.getInstance(s);
        entry.setMaxValidity(maxValidity);

        // EXTRA_CONTROL
        key = "EXTRA_CONTROL";
        s = getStrProp(props, key, false);
        if(s != null)
        {
            entry.setExtraControl(s);
        }

        // PERMISSIONS
        key = "PERMISSIONS";
        s = getStrProp(props, key, true);
        Set<String> permissions = StringUtil.splitAsSet(s, ", ");
        Set<Permission> _permissions = new HashSet<>();
        for(String permission : permissions)
        {
            Permission _permission = Permission.getPermission(permission);
            if(_permission == null)
            {
                throw new IllegalCmdParamException("invalid permission: " + permission);
            }
            _permissions.add(_permission);
        }
        entry.setPermissions(_permissions);

        // REVOKED
        key = "REVOKED";
        s = getStrProp(props, key, true);
        boolean revoked;
        if("true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s))
        {
            revoked = true;
        }
        else if("false".equalsIgnoreCase(s) || "no".equalsIgnoreCase(s))
        {
            revoked = false;
        }
        else
        {
            throw new IllegalCmdParamException("invalid " + key + ": '" + s + "'");
        }

        if(revoked)
        {
            // REV_REASON
            key = "REV_REASON";
            int reasonCode = getRequiredIntProp(props, key);

            // REV_TIME
            key = "REV_TIME";
            Date revocationTime = new Date(getRequiredLongProp(props, key) * 1000);

            // REV_INV_TIME
            key = "REV_INV_TIME";
            Long t = getLongProp(props, key, false);
            Date invalidityTime = null;
            if(t != null)
            {
                invalidityTime = new Date(t.longValue() * 1000);
            }
            CertRevocationInfo revInfo = new CertRevocationInfo(
                    reasonCode, revocationTime, invalidityTime);
            entry.setRevocationInfo(revInfo);
        }

        // CERT
        if(ignoreCert == false)
        {
            key = "CERT";
            s = getStrProp(props, key, false);
            byte[] certBytes = null;
            if(s != null)
            {
                if(StringUtil.startsWithIgnoreCase(s, "file:"))
                {
                    certBytes = IoUtil.read(s.substring("file:".length()));
                }
                else
                {
                    certBytes = Base64.decode(s);
                }
            }

            X509Certificate caCert = null;
            if(certBytes != null)
            {
                caCert = X509Util.parseCert(certBytes);
            }
            entry.setCertificate(caCert);
        }

        return entry;
    }

    private String getStrProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException
    {
        String s = props.getProperty(propKey);
        if(StringUtil.isBlank(s))
        {
            s = "";
        }
        else
        {
            s = s.trim();
        }

        if(s.isEmpty() == false)
        {
            return s;
        }

        if(required)
        {
            throw new IllegalCmdParamException("Required property '" + propKey + "' is not defined");
        }
        else
        {
            return null;
        }
    }

    private int getRequiredIntProp(
            final Properties props,
            final String propKey)
    throws IllegalCmdParamException
    {
        return getIntProp(props, propKey, true).intValue();
    }

    private Integer getIntProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException
    {
        String s = getStrProp(props, propKey, required);
        return s == null ? null : Integer.parseInt(s);
    }

    private long getRequiredLongProp(
            final Properties props,
            final String propKey)
    throws IllegalCmdParamException
    {
        return getLongProp(props, propKey, true).longValue();
    }

    private Long getLongProp(
            final Properties props,
            final String propKey,
            final boolean required)
    throws IllegalCmdParamException
    {
        String s = getStrProp(props, propKey, required);
        return s == null ? null : Long.parseLong(s);
    }

    private static void assertNotNull(
            final Object obj,
            final String key,
            final String value)
    throws IllegalCmdParamException
    {
        if(obj == null)
        {
            throw new IllegalCmdParamException("invalid " + key + ": '" + value + "'");
        }
    }
}
