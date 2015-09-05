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

package org.xipki.security.shell.loadtest.p11;

import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.qa.AbstractLoadTest;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.api.p11.P11WritableSlot;

/**
 * @author Lijun Liao
 */

public abstract class P11KeyGenLoadTest extends AbstractLoadTest
{
    protected final P11WritableSlot slot;

    private AtomicLong l = new AtomicLong(System.currentTimeMillis());

    protected abstract void genKeypair()
    throws Exception;

    public P11KeyGenLoadTest(
            final P11WritableSlot slot)
    {
        ParamUtil.assertNotNull("slot", slot);
        this.slot = slot;
    }

    protected String getDummyLabel()
    {
        return "loadtest-" + l.getAndIncrement();
    }

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    class Testor implements Runnable
    {
        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                try
                {
                    genKeypair();
                    account(1, 0);
                }catch(Exception e)
                {
                    account(1, 1);
                }
            }
        }
    }
}
