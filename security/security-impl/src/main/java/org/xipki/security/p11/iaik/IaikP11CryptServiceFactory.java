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

package org.xipki.security.p11.iaik;

import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.p11.P11Control;
import org.xipki.security.api.p11.P11CryptService;
import org.xipki.security.api.p11.P11CryptServiceFactory;
import org.xipki.security.api.p11.P11ModuleConf;

/**
 * @author Lijun Liao
 */

public class IaikP11CryptServiceFactory implements P11CryptServiceFactory
{
    private P11Control p11Control;

    @Override
    public void init(
            final P11Control p11Control)
    {
        ParamUtil.assertNotNull("p11Control", p11Control);
        this.p11Control = p11Control;
        IaikP11ModulePool.getInstance().setDefaultModuleName(p11Control.getDefaultModuleName());
    }

    @Override
    public P11CryptService createP11CryptService(
            String moduleName)
    throws SignerException
    {
        if(p11Control == null)
        {
            throw new IllegalStateException("please call init() first");
        }

        ParamUtil.assertNotNull("moduleName", moduleName);

        if(SecurityFactory.DEFAULT_P11MODULE_NAME.equals(moduleName))
        {
            moduleName = p11Control.getDefaultModuleName();
        }

        P11ModuleConf conf = p11Control.getModuleConf(moduleName);
        if(conf == null)
        {
            throw new SignerException("PKCS#11 module " + moduleName + " is not defined");
        }

        return IaikP11CryptService.getInstance(conf);
    }

}
