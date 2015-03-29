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

package org.xipki.ca.server.mgmt.api;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class CAEntry
{
    private String name;
    private CAStatus status;
    private CertValidity maxValidity;
    private String signerType;
    private String signerConf;
    private String cmpControlName;
    private DuplicationMode duplicateKeyMode;
    private DuplicationMode duplicateSubjectMode;
    private ValidityMode validityMode = ValidityMode.STRICT;
    private Set<Permission> permissions;
    private int expirationPeriod;
    private String extraControl;

    public CAEntry(
            final String name,
            final String signerType,
            final String signerConf,
            final int expirationPeriod)
    throws CAMgmtException
    {
        ParamChecker.assertNotBlank("name", name);
        ParamChecker.assertNotBlank("signerType", signerType);

        if(expirationPeriod < 0)
        {
            throw new IllegalArgumentException("expirationPeriod is negative (" + expirationPeriod + " < 0)");
        }
        this.expirationPeriod = expirationPeriod;

        this.name = name.toUpperCase();
        this.signerType = signerType;
        this.signerConf = signerConf;
    }

    public String getName()
    {
        return name;
    }

    public CertValidity getMaxValidity()
    {
        return maxValidity;
    }

    public void setMaxValidity(
            final CertValidity maxValidity)
    {
        this.maxValidity = maxValidity;
    }

    public String getSignerConf()
    {
        return signerConf;
    }

    public CAStatus getStatus()
    {
        return status;
    }
    public void setStatus(
            final CAStatus status)
    {
        this.status = status;
    }

    public String getSignerType()
    {
        return signerType;
    }

    public void setCmpControlName(
            final String name)
    {
        this.cmpControlName = name;
    }

    public String getCmpControlName()
    {
        return cmpControlName;
    }

    public DuplicationMode getDuplicateKeyMode()
    {
        return duplicateKeyMode;
    }

    public void setDuplicateKeyMode(
            final DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateKeyMode = mode;
    }

    public DuplicationMode getDuplicateSubjectMode()
    {
        return duplicateSubjectMode;
    }

    public void setDuplicateSubjectMode(
            final DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateSubjectMode = mode;
    }

    public ValidityMode getValidityMode()
    {
        return validityMode;
    }

    public void setValidityMode(
            final ValidityMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.validityMode = mode;
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public String getPermissionsAsText()
    {
        return toString(permissions);
    }

    public void setPermissions(
            final Set<Permission> permissions)
    {
        this.permissions = (permissions == null) ? null : Collections.unmodifiableSet(permissions);
    }

    public int getExpirationPeriod()
    {
        return expirationPeriod;
    }

    public String getExtraControl()
    {
        return extraControl;
    }

    public void setExtraControl(
            final String extraControl)
    {
        this.extraControl = extraControl;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(
            final boolean verbose)
    {
        return toString(verbose, true);
    }

    public String toString(
            final boolean verbose,
            final boolean ignoreSensitiveInfo)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("status: ").append(status.getStatus()).append('\n');
        sb.append("maxValidity: ").append(maxValidity).append("\n");
        sb.append("expirationPeriod: ").append(expirationPeriod).append(" days\n");
        sb.append("signerType: ").append(signerType).append('\n');
        sb.append("signerConf: ");
        if(signerConf == null)
        {
            sb.append("null");
        } else
        {
            sb.append(SecurityUtil.signerConfToString(signerConf, verbose, ignoreSensitiveInfo));
        }
        sb.append('\n');
        sb.append("cmpcontrolName: ").append(cmpControlName).append('\n');
        sb.append("duplicateKey: ").append(duplicateKeyMode.getDescription()).append('\n');
        sb.append("duplicateSubject: ").append(duplicateSubjectMode.getDescription()).append('\n');
        sb.append("validityMode: ").append(validityMode).append('\n');
        sb.append("permissions: ").append(Permission.toString(permissions)).append('\n');
        sb.append("extraControl: ").append(extraControl).append('\n');

        return sb.toString();
    }

    protected static String toString(
            final Collection<? extends Object> tokens)
    {
        if(CollectionUtil.isEmpty(tokens))
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        int size = tokens.size();
        int idx = 0;
        for(Object token : tokens)
        {
            sb.append(token);
            if(idx++ < size - 1)
            {
                sb.append(", ");
            }
        }
        return sb.toString();
    }

}
