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

package org.xipki.ocsp.server.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.xipki.common.InvalidConfException;
import org.xipki.ocsp.api.OCSPMode;
import org.xipki.ocsp.server.impl.jaxb.ResponderType;

/**
 * @author Lijun Liao
 */

class ResponderOption
{
    private final OCSPMode mode;
    private final boolean inheritCaRevocation;
    private final String requestOptionName;
    private final String responseOptionName;
    private final String auditOptionName;
    private final String certprofileOptionName;
    private final String signerName;
    private final List<String> storeNames;
    private final List<String> servletPaths;

    public ResponderOption(
            final ResponderType conf)
    throws InvalidConfException
    {
        String s = conf.getMode();
        if(s == null || "RFC6960".equalsIgnoreCase(s))
        {
            this.mode = OCSPMode.RFC6960;
        }
        else if("RFC2560".equalsIgnoreCase(s))
        {
            this.mode = OCSPMode.RFC2560;
        }
        else
        {
            throw new InvalidConfException("invalid OCSP mode '" + s + "'");
        }

        this.signerName = conf.getSigner();
        this.requestOptionName = conf.getRequest();
        this.responseOptionName = conf.getResponse();
        this.auditOptionName = conf.getAudit();
        this.certprofileOptionName = conf.getCertprofile();
        this.inheritCaRevocation = conf.isInheritCaRevocation();

        List<String> list = new ArrayList<>(conf.getStores().getStore());
        this.storeNames = Collections.unmodifiableList(list);

        if(conf.getServletPaths() == null)
        {
            this.servletPaths = Collections.emptyList();
        }
        else
        {
            List<String> paths = conf.getServletPaths().getServletPath();
            for(String path : paths)
            {
                int n = path.length();
                if(n > 0 && path.charAt(0) == '/')
                {
                    throw new InvalidConfException("servlet path '" + path + "' must not start with '/'");
                }
                if(n > 1 && path.charAt(n - 1) == '/')
                {
                    throw new InvalidConfException("servlet path '" + path + "' must not end with '/'");
                }
            }
            list = new ArrayList<>(paths);
            this.servletPaths = Collections.unmodifiableList(list);
        }
    }

    public OCSPMode getMode()
    {
        return mode;
    }

    public boolean isInheritCaRevocation()
    {
        return inheritCaRevocation;
    }

    public String getSignerName()
    {
        return signerName;
    }

    public String getRequestOptionName()
    {
        return requestOptionName;
    }

    public String getResponseOptionName()
    {
        return responseOptionName;
    }

    public String getAuditOptionName()
    {
        return auditOptionName;
    }

    public List<String> getStoreNames()
    {
        return storeNames;
    }

    public String getCertprofileOptionName()
    {
        return certprofileOptionName;
    }

    public List<String> getServletPaths()
    {
        return servletPaths;
    }

}
