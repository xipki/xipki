/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security;

import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.StringUtil;

/**
 * @author Lijun Liao
 */

public class HttpsHostnameVerifier implements HostnameVerifier
{
    private static final Logger LOG = LoggerFactory.getLogger(HttpsHostnameVerifier.class);

    private boolean enabled = false;
    private boolean trustAll = false;

    private Map<String, Set<String>> hostnameMap = new ConcurrentHashMap<>();
    private HostnameVerifier oldHostnameVerifier = null;
    private boolean meAsDefaultHostnameVerifier = false;

    public void init()
    {
        LOG.info("enabled: {}", enabled);
        LOG.info("trustAll: {}", trustAll);
        if(enabled)
        {
            oldHostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
            LOG.info("Register me as DefaulHostnameVerifier, and backup the old one " + oldHostnameVerifier);
            HttpsURLConnection.setDefaultHostnameVerifier(this);
            meAsDefaultHostnameVerifier = true;
        }
    }

    public void shutdown()
    {
        if(meAsDefaultHostnameVerifier && HttpsURLConnection.getDefaultHostnameVerifier() == this)
        {
            LOG.info("Unregister me as DefaultHostnameVerifier, and reuse the old one " + oldHostnameVerifier);
            HttpsURLConnection.setDefaultHostnameVerifier(oldHostnameVerifier);
            meAsDefaultHostnameVerifier = false;
        }
    }

    /**
     * Verify that the host name is an acceptable match with
     * the server's authentication scheme.
     *
     * @param hostname the host name
     * @param session SSLSession used on the connection to host
     * @return true if the host name is acceptable
     */
    @Override
    public boolean verify(String hostname, SSLSession session)
    {
        if(trustAll)
        {
            return true;
        }

        LOG.info("hostname: {}", hostname);
        String commonName = null;
        try
        {
            Principal peerPrincipal = session.getPeerPrincipal();
            if(peerPrincipal == null)
            {
                return false;
            }
            commonName = IoCertUtil.getCommonName(new X500Name(peerPrincipal.getName()));
            LOG.info("commonName: {}", commonName);
        }catch(Exception e)
        {
            LOG.error("Error: {}", e.getMessage());
            return false;
        }

        Set<String> hostnames = hostnameMap.get(commonName);
        return hostnames == null ? false : hostnames.contains(hostname);
    }

    public void setCommonnameHostMap(String commonnameHostMap)
    {
        hostnameMap.clear();
        if(commonnameHostMap == null || commonnameHostMap.isEmpty())
        {
            return;
        }

        CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(commonnameHostMap);
        Set<String> commonNames = utf8Pairs.getNames();
        for(String commonName :commonNames)
        {
            String v = utf8Pairs.getValue(commonName);
            Set<String> hosts = StringUtil.splitAsSet(v, ",; \t");
            hostnameMap.put(commonName, hosts);
        }
    }

    public boolean isEnabled()
    {
        return enabled;
    }

    public void setEnabled(boolean enabled)
    {
        this.enabled = enabled;
    }

    public boolean isTrustAll()
    {
        return trustAll;
    }

    public void setTrustAll(boolean trustAll)
    {
        this.trustAll = trustAll;
    }

}
