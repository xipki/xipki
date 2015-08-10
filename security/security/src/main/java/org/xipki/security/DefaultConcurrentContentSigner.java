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

package org.xipki.security;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.LogUtil;
import org.xipki.password.api.PasswordResolver;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

public class DefaultConcurrentContentSigner implements ConcurrentContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConcurrentContentSigner.class);

    private static int defaultSignServiceTimeout = 10000; // 10 seconds

    private final AlgorithmIdentifier algorithmIdentifier;
    private final BlockingDeque<ContentSigner> idleSigners = new LinkedBlockingDeque<>();
    private final BlockingDeque<ContentSigner> busySigners = new LinkedBlockingDeque<>();
    private final PrivateKey privateKey;

    private X509Certificate[] certificateChain;
    private X509CertificateHolder[] certificateChainAsBCObjects;

    static
    {
        String v = System.getProperty("org.xipki.signservice.timeout");
        if(v != null)
        {
            int vi = Integer.parseInt(v);
            // valid value is between 0 and 60 seconds
            if(vi < 0 || vi > 60 * 1000)
            {
                LOG.error("invalid org.xipki.signservice.timeout: {}", vi);
            }
            else
            {
                LOG.info("use org.xipki.signservice.timeout: {}", vi);
                defaultSignServiceTimeout = vi;
            }
        }
    }

    public DefaultConcurrentContentSigner(
            final List<ContentSigner> signers)
    {
        this(signers, null);
    }

    public DefaultConcurrentContentSigner(
            final List<ContentSigner> signers,
            final PrivateKey privateKey)
    {
        ParamChecker.assertNotEmpty("signers", signers);

        this.algorithmIdentifier = signers.get(0).getAlgorithmIdentifier();
        for(ContentSigner signer : signers)
        {
            idleSigners.addLast(signer);
        }

        this.privateKey = privateKey;
    }

    public ContentSigner borrowContentSigner()
    throws NoIdleSignerException
    {
        return borrowContentSigner(defaultSignServiceTimeout);
    }

    @Override
    public ContentSigner borrowContentSigner(
            final int soTimeout)
    throws NoIdleSignerException
    {
        ContentSigner signer = null;
        try
        {
            if(soTimeout == 0)
            {
                signer = idleSigners.takeFirst();
            }
            else
            {
                signer = idleSigners.pollFirst(soTimeout, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e)
        {
            LOG.info("interrupted");
        }

        if(signer == null)
        {
            throw new NoIdleSignerException("no idle signer available");
        }

        busySigners.addLast(signer);
        return signer;
    }

    @Override
    public void returnContentSigner(
            final ContentSigner signer)
    {
        ParamChecker.assertNotNull("signer", signer);

        boolean isBusySigner = busySigners.remove(signer);
        if(isBusySigner)
        {
            idleSigners.addLast(signer);
        }
        else
        {
            final String msg = "signer has not been borrowed before or has been returned more than once: " + signer;
            LOG.error(msg);
            throw new IllegalStateException(msg);
        }
    }

    @Override
    public void initialize(
            final String conf,
            final PasswordResolver passwordResolver)
    throws SignerException
    {
    }

    @Override
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    @Override
    public void setCertificateChain(
            final X509Certificate[] certificateChain)
    {
        this.certificateChain = certificateChain;
        if(this.certificateChain == null)
        {
            this.certificateChainAsBCObjects = null;
            return;
        }

        final int n = certificateChain.length;
        this.certificateChainAsBCObjects = new X509CertificateHolder[n];
        for(int i = 0; i < n; i++)
        {
            X509Certificate cert = this.certificateChain[i];
            try
            {
                this.certificateChainAsBCObjects[i] = new X509CertificateHolder(cert.getEncoded());
            } catch (CertificateEncodingException | IOException e)
            {
                throw new IllegalArgumentException(e.getClass().getName() + " occured while"
                        + " parsing certificate at index " + i + ": " + e.getMessage(), e);
            }
        }
    }

    @Override
    public X509Certificate getCertificate()
    {
        if(certificateChain != null && certificateChain.length > 0)
        {
            return certificateChain[0];
        }
        else
        {
            return null;
        }
    }

    @Override
    public X509CertificateHolder getCertificateAsBCObject()
    {
        if(certificateChainAsBCObjects != null && certificateChainAsBCObjects.length > 0)
        {
            return certificateChainAsBCObjects[0];
        }
        else
        {
            return null;
        }
    }

    @Override
    public X509Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    @Override
    public X509CertificateHolder[] getCertificateChainAsBCObjects()
    {
        return certificateChainAsBCObjects;
    }

    @Override
    public boolean isHealthy()
    {
        ContentSigner signer = null;
        try
        {
            signer = borrowContentSigner();
            OutputStream stream = signer.getOutputStream();
            stream.write(new byte[]{1,2,3,4});
            byte[] signature = signer.getSignature();
            return signature != null && signature.length > 0;
        } catch(Exception e)
        {
            final String message = "isHealthy()";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
            }
            LOG.debug(message, e);
            return false;
        }
        finally
        {
            if(signer != null)
            {
                returnContentSigner(signer);
            }
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    @Override
    public void shutdown()
    {
    }

}
