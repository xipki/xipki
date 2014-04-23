/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.security;

import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

public class DefaultConcurrentContentSigner implements ConcurrentContentSigner
{
    private static final Logger LOG = LoggerFactory.getLogger(DefaultConcurrentContentSigner.class);

    private final BlockingQueue<ContentSigner> idleSigners = new LinkedBlockingQueue<ContentSigner>();
    private final BlockingQueue<ContentSigner> busySigners = new LinkedBlockingQueue<ContentSigner>();
    private final PrivateKey privateKey;

    private X509Certificate certificate;

    public DefaultConcurrentContentSigner(List<ContentSigner> signers)
    {
        this(signers, null);
    }

    public DefaultConcurrentContentSigner(List<ContentSigner> signers, PrivateKey privateKey)
    {
        ParamChecker.assertNotEmpty("signers", signers);

        for(ContentSigner signer : signers)
        {
            idleSigners.add(signer);
        }

        this.privateKey = privateKey;
    }

    public ContentSigner borrowContentSigner()
    throws NoIdleSignerException
    {
        ContentSigner signer = idleSigners.poll();
        if(signer == null)
        {
            throw new NoIdleSignerException("No idle signer available");
        }

        busySigners.add(signer);
        return signer;
    }

    @Override
    public ContentSigner borrowContentSigner(int soTimeout)
    throws NoIdleSignerException
    {
        if(soTimeout == 0)
        {
            return borrowContentSigner();
        }

        long till = System.currentTimeMillis() + soTimeout;
        long timeout = soTimeout;

        ContentSigner signer = null;
        while(timeout > 0)
        {
            try
            {
                signer = idleSigners.poll(timeout, TimeUnit.MILLISECONDS);
            }catch(InterruptedException e)
            {
                LOG.trace("interrupted");
            }

            if(signer != null)
            {
                break;
            }

            timeout = till - System.currentTimeMillis();
        }

        if(signer == null)
        {
            throw new NoIdleSignerException("No idle signer available");
        }

        busySigners.add(signer);
        return signer;
    }

    @Override
    public void returnContentSigner(ContentSigner signer)
    {
        ParamChecker.assertNotNull("signer", signer);

        boolean isBusySigner = busySigners.remove(signer);
        if(isBusySigner)
        {
            idleSigners.add(signer);
        }
        else
        {
            final String msg = "signer has not been borrowed before or has been returned more than once: " + signer;
            LOG.error(msg);
            throw new IllegalStateException(msg);
        }
    }

    @Override
    public void initialize(String conf, PasswordResolver passwordResolver)
    throws SignerException
    {
    }

    @Override
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    @Override
    public void setCertificate(X509Certificate certificate)
    {
        this.certificate = certificate;
    }

    @Override
    public X509Certificate getCertificate()
    {
        return certificate;
    }

    @Override
    public boolean isHealthy()
    {
        ContentSigner signer = null;
        try
        {
            signer = borrowContentSigner(60000); // wait for maximal 60 seconds
            OutputStream stream = signer.getOutputStream();
            stream.write(new byte[]{1,2,3,4});
            byte[] signature = signer.getSignature();
            return signature != null && signature.length > 0;
        } catch(Exception e)
        {
            LOG.error("healthCheck(). {}: {}", e.getClass().getName(), e.getMessage());
            LOG.debug("healthCheck()", e);
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
}
