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

package org.xipki.ca.server.mgmt.qa.shell;

import java.rmi.UnexpectedException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.commands.Command;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.api.X509ChangeCAEntry;
import org.xipki.ca.server.mgmt.shell.CaUpdateCommand;
import org.xipki.common.security.CmpUtf8Pairs;
import org.xipki.console.karaf.CmdFailure;

/**
 * @author Lijun Liao
 */

@Command(scope = "xipki-caqa", name = "ca-check", description="check information of CAs (QA)")
public class CaCheckCommand extends CaUpdateCommand
{
    @Override
    protected Object _doExecute()
    throws Exception
    {
        X509ChangeCAEntry ey = getChangeCAEntry();
        String caName = ey.getName();
        out("checking CA" + caName);

        CAEntry entry = caManager.getCA(caName);
        if(entry == null)
        {
            throw new UnexpectedException("could not find CA '" + caName + "'");
        }

        if(entry instanceof X509CAEntry == false)
        {
            throw new UnexpectedException("CA '" + caName + "' is not an X509-CA");
        }

        X509CAEntry ca = (X509CAEntry) entry;

        // CA cert uris
        if(ey.getCaCertUris() != null)
        {
            List<String> ex = ey.getCaCertUris();
            List<String> is = ca.getCacertUris();
            MgmtQAShellUtil.assertEquals("CA cert uris", ex, is);
        }

        // CA certificate
        if(ey.getCert() != null)
        {
            X509Certificate ex = ey.getCert();
            X509Certificate is = ca.getCertificate();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("CA cert is not as expected");
            }
        }

        // CMP control name
        if(ey.getCmpControlName() != null)
        {
            String ex = ey.getCmpControlName();
            String is = ca.getCmpControlName();
            MgmtQAShellUtil.assertEquals("CMP control name", ex, is);
        }

        // CRL signer name
        if(ey.getCrlSignerName() != null)
        {
            String ex = ey.getCrlSignerName();
            String is = ca.getCrlSignerName();
            MgmtQAShellUtil.assertEquals("CRL signer name", ex, is);
        }

        // CRL uris
        if(ey.getCrlUris() != null)
        {
            List<String> ex = ey.getCrlUris();
            List<String> is = ca.getCrlUris();
            MgmtQAShellUtil.assertEquals("CRL uris", ex, is);
        }

        // DeltaCRL uris
        if(ey.getDeltaCrlUris() != null)
        {
            List<String> ex = ey.getDeltaCrlUris();
            List<String> is = ca.getDeltaCrlUris();
            MgmtQAShellUtil.assertEquals("Delta CRL uris", ex, is);
        }

        // Duplicate key mode
        if(ey.getDuplicateKeyMode() != null)
        {
            DuplicationMode ex = ey.getDuplicateKeyMode();
            DuplicationMode is = ca.getDuplicateKeyMode();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("Duplicate key mode: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Duplicate subject mode
        if(ey.getDuplicateSubjectMode() != null)
        {
            DuplicationMode ex = ey.getDuplicateSubjectMode();
            DuplicationMode is = ca.getDuplicateSubjectMode();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("Duplicate subject mode: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Expiration period
        if(ey.getExpirationPeriod() != null)
        {
            Integer ex = ey.getExpirationPeriod();
            Integer is = ca.getExpirationPeriod();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("Expiration period: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Extra control
        if(ey.getExtraControl() != null)
        {
            String ex = ey.getExtraControl();
            String is = ca.getExtraControl();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("Extra control: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Max validity
        if(ey.getMaxValidity() != null)
        {
            CertValidity ex = ey.getMaxValidity();
            CertValidity is = ca.getMaxValidity();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("Max validity: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Num CRLs
        if(ey.getNumCrls() != null)
        {
            int ex = ey.getNumCrls();
            int is = ca.getNumCrls();
            if(ex != is)
            {
                throw new CmdFailure("num CRLs: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // OCSP uris
        if(ey.getOcspUris() != null)
        {
            List<String> ex = ey.getOcspUris();
            List<String> is = ca.getOcspUris();
            MgmtQAShellUtil.assertEquals("OCSP uris", ex, is);
        }

        // Permissions
        if(ey.getPermissions() != null)
        {
            Set<Permission> ex = ey.getPermissions();
            Set<Permission> is = ca.getPermissions();
            MgmtQAShellUtil.assertEquals("permissions", ex, is);
        }

        // Responder name
        if(ey.getResponderName() != null)
        {
            String ex = ey.getResponderName();
            String is = ca.getResponderName();
            MgmtQAShellUtil.assertEquals("responder name", ex, is);
        }

        // Signer Type
        if(ey.getSignerType() != null)
        {
            String ex = ey.getSignerType();
            String is = ca.getSignerType();
            MgmtQAShellUtil.assertEquals("signer type", ex, is);
        }

        if(ey.getSignerConf() != null)
        {
            CmpUtf8Pairs ex = new CmpUtf8Pairs(ey.getSignerConf());
            ex.removeUtf8Pair("keystore");
            CmpUtf8Pairs is = new CmpUtf8Pairs(ca.getSignerConf());
            is.removeUtf8Pair("keystore");
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("signer conf: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // Status
        if(ey.getStatus() != null)
        {
            CAStatus ex = ey.getStatus();
            CAStatus is = ca.getStatus();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("status: is '" + is + "', but expected '" + ex + "'");
            }
        }

        // validity mode
        if(ey.getValidityMode() != null)
        {
            ValidityMode ex = ey.getValidityMode();
            ValidityMode is = ca.getValidityMode();
            if(ex.equals(is) == false)
            {
                throw new CmdFailure("validity mode: is '" + is + "', but expected '" + ex + "'");
            }
        }

        out(" checked CA" + caName);
        return null;
    }
}
