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

package org.xipki.security.shell.loadtest.p12;

import java.io.File;
import java.security.cert.X509Certificate;

import org.bouncycastle.operator.ContentSigner;
import org.xipki.common.qa.AbstractLoadTest;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.P12KeypairGenerationResult;
import org.xipki.security.api.SecurityFactory;

/**
 * @author Lijun Liao
 */

public abstract class P12SignLoadTest extends AbstractLoadTest
{
    private final ConcurrentContentSigner signer;
    private final String keystoreFile;
    protected final static String password = "1234";

    public P12SignLoadTest(
            final SecurityFactory securityFactory,
            final String signatureAlgorithm,
            final P12KeypairGenerationResult kpGenResult)
    throws Exception
    {
        ParamUtil.assertNotNull("securityFactory", securityFactory);
        ParamUtil.assertNotBlank("signatureAlgorithm", signatureAlgorithm);
        ParamUtil.assertNotNull("kpGenResult", kpGenResult);

        keystoreFile = "tmp-loadtest-" + System.currentTimeMillis() + ".p12";
        IoUtil.save(keystoreFile, kpGenResult.getKeystore());
        String signerConf = SecurityFactoryImpl.getKeystoreSignerConf(
                keystoreFile, password, signatureAlgorithm, 20);;
        this.signer = securityFactory.createSigner("PKCS12", signerConf, (X509Certificate) null);
    }

    private void close()
    {
        new File(keystoreFile).delete();
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
            ContentSigner singleSigner;
            try
            {
                singleSigner = signer.borrowContentSigner();
            } catch (NoIdleSignerException e)
            {
                account(1, 1);
                return;
            }

            while(stop() == false && getErrorAccout() < 1)
            {
                try
                {
                    singleSigner.getOutputStream().write(new byte[]{1, 2, 3, 4});
                    singleSigner.getSignature();
                    account(1, 0);
                }catch(Exception e)
                {
                    account(1, 1);
                }
            }

            signer.returnContentSigner(singleSigner);
            close();
        }
    }

}
