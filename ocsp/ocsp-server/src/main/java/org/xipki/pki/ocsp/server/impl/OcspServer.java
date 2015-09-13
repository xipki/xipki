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

package org.xipki.pki.ocsp.server.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditChildEvent;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditService;
import org.xipki.audit.api.AuditServiceRegister;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.common.ConfPairs;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XMLUtil;
import org.xipki.datasource.api.DataSourceFactory;
import org.xipki.datasource.api.DataSourceWrapper;
import org.xipki.datasource.api.exception.DataAccessException;
import org.xipki.pki.ocsp.api.CertStatus;
import org.xipki.pki.ocsp.api.CertStatusInfo;
import org.xipki.pki.ocsp.api.CertStatusStore;
import org.xipki.pki.ocsp.api.CertStatusStoreException;
import org.xipki.pki.ocsp.api.CertprofileOption;
import org.xipki.pki.ocsp.api.OCSPMode;
import org.xipki.pki.ocsp.server.impl.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.pki.ocsp.server.impl.certstore.CrlCertStatusStore;
import org.xipki.pki.ocsp.server.impl.certstore.DbCertStatusStore;
import org.xipki.pki.ocsp.server.impl.certstore.IssuerFilter;
import org.xipki.pki.ocsp.server.impl.jaxb.AuditOptionType;
import org.xipki.pki.ocsp.server.impl.jaxb.CertprofileOptionType;
import org.xipki.pki.ocsp.server.impl.jaxb.CrlStoreType;
import org.xipki.pki.ocsp.server.impl.jaxb.CustomStoreType;
import org.xipki.pki.ocsp.server.impl.jaxb.DatasourceType;
import org.xipki.pki.ocsp.server.impl.jaxb.DbStoreType;
import org.xipki.pki.ocsp.server.impl.jaxb.EmbedCertsMode;
import org.xipki.pki.ocsp.server.impl.jaxb.ExcludesFileOrValueType;
import org.xipki.pki.ocsp.server.impl.jaxb.FileOrPlainValueType;
import org.xipki.pki.ocsp.server.impl.jaxb.FileOrValueType;
import org.xipki.pki.ocsp.server.impl.jaxb.IncludesFileOrValueType;
import org.xipki.pki.ocsp.server.impl.jaxb.OCSPServer;
import org.xipki.pki.ocsp.server.impl.jaxb.ObjectFactory;
import org.xipki.pki.ocsp.server.impl.jaxb.RequestOptionType;
import org.xipki.pki.ocsp.server.impl.jaxb.ResponderType;
import org.xipki.pki.ocsp.server.impl.jaxb.ResponseOptionType;
import org.xipki.pki.ocsp.server.impl.jaxb.SignerType;
import org.xipki.pki.ocsp.server.impl.jaxb.StoreType;
import org.xipki.pki.ocsp.server.impl.jaxb.StoreType.Source;
import org.xipki.password.api.PasswordResolverException;
import org.xipki.security.api.CRLReason;
import org.xipki.security.api.CertRevocationInfo;
import org.xipki.security.api.CertpathValidationModel;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.HashAlgoType;
import org.xipki.security.api.NoIdleSignerException;
import org.xipki.security.api.ObjectIdentifiers;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.api.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class OcspServer
{
    private static class ServletPathResponderName implements Comparable<ServletPathResponderName>
    {
        private final String path;
        private final String responderName;

        public ServletPathResponderName(
                final String path,
                final String responderName)
        {
            ParamUtil.assertNotNull("path", path);
            ParamUtil.assertNotBlank("responderName", responderName);

            this.path = path;
            this.responderName = responderName;
        }

        public String getPath()
        {
            return path;
        }

        public String getResponderName()
        {
            return responderName;
        }

        @Override
        public int compareTo(
                final ServletPathResponderName o)
        {
            int d = o.path.length() - path.length();
            if(d == 0)
            {
                return 0;
            }

            return (d > 0)
                    ? 1
                    : -1;
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(OcspServer.class);

    public static final long defaultCacheMaxAge = 60; // 1 minute

    private DataSourceFactory dataSourceFactory;
    private SecurityFactory securityFactory;

    private String confFile;
    private AuditServiceRegister auditServiceRegister;

    private Map<String, Responder> responders = new HashMap<>();
    private Map<String, ResponderSigner> signers = new HashMap<>();
    private Map<String, RequestOption> requestOptions = new HashMap<>();
    private Map<String, ResponseOption> responseOptions = new HashMap<>();
    private Map<String, AuditOption> auditOptions = new HashMap<>();
    private Map<String, CertprofileOption> certprofileOptions = new HashMap<>();
    private Map<String, CertStatusStore> stores = new HashMap<>();
    private List<ServletPathResponderName> servletPaths = new ArrayList<>();

    public OcspServer()
    {
    }

    public void setSecurityFactory(
            final SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    public void setDataSourceFactory(
            final DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public void setConfFile(
            final String confFile)
    {
        this.confFile = confFile;
    }

    public ResponderAndRelativeUri getResponderAndRelativeUri(
            final HttpServletRequest request)
    throws UnsupportedEncodingException
    {
        String requestURI = request.getRequestURI();
        String servletPath = request.getServletPath();

        String path = "";
        int n = servletPath.length();
        if(requestURI.length() > n + 1)
        {
            path = requestURI.substring(n + 1);
        }

        ServletPathResponderName entry = null;
        for(ServletPathResponderName m : servletPaths)
        {
            if(path.startsWith(m.getPath()))
            {
                entry = m;
                break;
            }
        }

        if(entry == null)
        {
            return null;
        }

        String relativeUri = "";
        if(entry.getPath().length() > 0)
        {
            n += 1 + entry.getPath().length();
        }

        if(requestURI.length() > n + 1)
        {
            relativeUri = requestURI.substring(n + 1);
            relativeUri = URLDecoder.decode(relativeUri, "UTF-8");
        }

        return new ResponderAndRelativeUri(responders.get(entry.getResponderName()),
                relativeUri);
    }

    public Responder getResponder(
            final String name)
    {
        return responders.get(name);
    }

    public void init()
    throws InvalidConfException, PasswordResolverException, DataAccessException
    {
        boolean successfull = false;
        try
        {
            do_init();
            successfull = true;
        }finally
        {
            if(successfull)
            {
                LOG.info("started OCSPResponder server");
            }
            else
            {
                LOG.error("could not start OCSPResponder server");
            }
            auditLogPCIEvent(successfull, "START");
        }
    }

    private void do_init()
    throws InvalidConfException, DataAccessException, PasswordResolverException
    {
        if(confFile == null)
        {
            throw new IllegalStateException("confFile is not set");
        }
        if(dataSourceFactory == null)
        {
            throw new IllegalStateException("dataSourceFactory is not set");
        }
        if(securityFactory == null)
        {
            throw new IllegalStateException("securityFactory is not set");
        }

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        OCSPServer conf = parseConf(confFile);

        // ----- check the duplication names
        Set<String> c = new HashSet<>();

        // Duplication name check: responder
        for(ResponderType m : conf.getResponders().getResponder())
        {
            String name = m.getName();
            if(c.contains(m))
            {
                throw new InvalidConfException("responder named '" + name + "' defined duplicatedly");
            }

            if(StringUtil.isBlank(name))
            {
                throw new InvalidConfException("responder name could not be empty");
            }

            for(int i = 0; i < name.length(); i++)
            {
                char ch = name.charAt(i);
                if(((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) == false)
                {
                    throw new InvalidConfException("invalid OCSP responder name '" + name + "'");
                }
            }
        }

        // Duplication name check: signer
        c.clear();
        for(SignerType m : conf.getSigners().getSigner())
        {
            String name = m.getName();
            if(c.contains(m))
            {
                throw new InvalidConfException("signer option named '" + name + "' defined duplicatedly");
            }
        }

        // Duplication name check: requests
        c.clear();
        for(RequestOptionType m : conf.getRequestOptions().getRequestOption())
        {
            String name = m.getName();
            if(c.contains(m))
            {
                throw new InvalidConfException("request option named '" + name + "' defined duplicatedly");
            }
        }

        // Duplication name check: response
        c.clear();
        for(ResponseOptionType m : conf.getResponseOptions().getResponseOption())
        {
            String name = m.getName();
            if(c.contains(m))
            {
                throw new InvalidConfException("response option named '" + name + "' defined duplicatedly");
            }
        }

        // Duplication name check: audit
        c.clear();
        if(conf.getAuditOptions() != null)
        {
            for(AuditOptionType m : conf.getAuditOptions().getAuditOption())
            {
                String name = m.getName();
                if(c.contains(m))
                {
                    throw new InvalidConfException("audit option named '" + name + "' defined duplicatedly");
                }
            }
        }

        // Duplication name check: store
        c.clear();
        for(StoreType m : conf.getStores().getStore())
        {
            String name = m.getName();
            if(c.contains(m))
            {
                throw new InvalidConfException("store named '" + name + "' defined duplicatedly");
            }
        }

        // Duplication name check: certprofile
        c.clear();
        if(conf.getCertprofileOptions() != null)
        {
            for(CertprofileOptionType m : conf.getCertprofileOptions().getCertprofileOption())
            {
                String name = m.getName();
                if(c.contains(m))
                {
                    throw new InvalidConfException("certprofile option named '" + name + "' defined duplicatedly");
                }
            }
        }

        // Duplication name check: datasource
        c.clear();
        if(conf.getDatasources() != null)
        {
            for(DatasourceType m : conf.getDatasources().getDatasource())
            {
                String name = m.getName();
                if(c.contains(m))
                {
                    throw new InvalidConfException("datasource named '" + name + "' defined duplicatedly");
                }
            }
        }

        // -- initializes the responders
        // signers
        for(SignerType m : conf.getSigners().getSigner())
        {
            ResponderSigner signer = initSigner(m);
            signers.put(m.getName(), signer);
        }

        // requests
        for(RequestOptionType m : conf.getRequestOptions().getRequestOption())
        {
            RequestOption option = new RequestOption(m);
            requestOptions.put(m.getName(), option);
        }

        // responses
        for(ResponseOptionType m : conf.getResponseOptions().getResponseOption())
        {
            ResponseOption option = new ResponseOption(m);
            responseOptions.put(m.getName(), option);
        }

        // audits
        if(conf.getAuditOptions() != null)
        {
            for(AuditOptionType m : conf.getAuditOptions().getAuditOption())
            {
                AuditOption option = new AuditOption(m);
                auditOptions.put(m.getName(), option);
            }
        }

        // certprofiles
        if(conf.getCertprofileOptions() != null)
        {
            for(CertprofileOptionType m : conf.getCertprofileOptions().getCertprofileOption())
            {
                CertprofileOption option = new CertprofileOption(m.getIncludes().getInclude(), m.getExcludes().getExclude());
                certprofileOptions.put(m.getName(), option);
            }
        }

        // datasources
        Map<String, DataSourceWrapper> datasources = new HashMap<>();
        if(conf.getDatasources() != null)
        {
            for(DatasourceType m : conf.getDatasources().getDatasource())
            {
                String name = m.getName();
                DataSourceWrapper datasource;
                InputStream dsStream = null;
                try
                {
                    dsStream = getInputStream(m.getConf());
                    datasource  = dataSourceFactory.createDataSource(name,
                                dsStream, securityFactory.getPasswordResolver());
                } catch(IOException e)
                {
                    throw new InvalidConfException(e.getMessage(), e);
                }
                finally
                {
                    close(dsStream);
                }
                datasources.put(name, datasource);
            }
        }

        // stores
        for(StoreType m : conf.getStores().getStore())
        {
            CertStatusStore store = initStore(m, datasources);
            stores.put(m.getName(), store);
        }

        Map<String, ResponderOption> responderOptions = new HashMap<>();
        // responders
        for(ResponderType m : conf.getResponders().getResponder())
        {
            ResponderOption option = new ResponderOption(m);
            String n = option.getAuditOptionName();
            if(n != null && auditOptions.containsKey(n) == false)
            {
                throw new InvalidConfException("no auditOption named '" + n + "' is defined");
            }

            n = option.getCertprofileOptionName();
            if(n != null && certprofileOptions.containsKey(n) == false)
            {
                throw new InvalidConfException("no certprofileOption named '" + n + "' is defined");
            }

            n = option.getRequestOptionName();
            if(requestOptions.containsKey(n) == false)
            {
                throw new InvalidConfException("no requestOption named '" + n + "' is defined");
            }

            n = option.getResponseOptionName();
            if(responseOptions.containsKey(n) == false)
            {
                throw new InvalidConfException("no responseOption named '" + n + "' is defined");
            }

            n = option.getSignerName();
            if(signers.containsKey(n) == false)
            {
                throw new InvalidConfException("no signer named '" + n + "' is defined");
            }

            List<String> names = option.getStoreNames();
            for(String name : names)
            {
                if(stores.containsKey(name) == false)
                {
                    throw new InvalidConfException("no store named '" + name + "' is defined");
                }
            }
            responderOptions.put(m.getName(), option);
        }

        // sort the servlet paths
        Set<String> pathTexts = new HashSet<>();
        for(String responderName : responderOptions.keySet())
        {
            ServletPathResponderName path = new ServletPathResponderName(responderName, responderName);
            pathTexts.add(path.getPath());
            this.servletPaths.add(path);
        }

        for(String name : responderOptions.keySet())
        {
            ResponderOption option = responderOptions.get(name);
            List<String> paths = option.getServletPaths();
            for(String path : paths)
            {
                if(pathTexts.contains(path))
                {
                    throw new InvalidConfException("duplicated definition of servlet path '" + path + "'");
                }
                this.servletPaths.add(new ServletPathResponderName(path, name));
            }
        }

        Collections.sort(this.servletPaths);

        // responders
        for(String name : responderOptions.keySet())
        {
            ResponderOption option = responderOptions.get(name);
            String aoName = option.getAuditOptionName();
            String cfoName = option.getCertprofileOptionName();

            List<CertStatusStore> _stores = new ArrayList<>(option.getStoreNames().size());
            for(String storeName : option.getStoreNames())
            {
                _stores.add(stores.get(storeName));
            }

            AuditOption auditOption = (aoName == null)
                    ? null
                    : auditOptions.get(aoName);

            CertprofileOption certprofileOption = (cfoName == null)
                    ? null
                    : certprofileOptions.get(cfoName);

            Responder responder = new Responder(
                    option,
                    requestOptions.get(option.getRequestOptionName()),
                    responseOptions.get(option.getResponseOptionName()),
                    auditOption,
                    certprofileOption,
                    signers.get(option.getSignerName()),
                    _stores);
            responders.put(name, responder);
        }
    }

    public void shutdown()
    {
        LOG.info("stopped OCSP Responder");
        for(CertStatusStore store : stores.values())
        {
            try
            {
                store.shutdown();
            }catch(Exception e)
            {
                final String message =  "shutdown store " + store.getName();
                if(LOG.isWarnEnabled())
                {
                    LOG.warn(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
            }
        }

        auditLogPCIEvent(true, "SHUTDOWN");
    }

    public OcspRespWithCacheInfo answer(
            final Responder responder,
            final OCSPReq request,
            final AuditEvent auditEvent,
            final boolean viaGet)
    {
        ResponderOption responderOption = responder.getResponderOption();
        RequestOption requestOption = responder.getRequestOption();
        ResponseOption responseOption = responder.getResponseOption();
        ResponderSigner signer = responder.getSigner();
        AuditOption auditOption = responder.getAuditOption();
        CertprofileOption certprofileOption = responder.getCertprofileOption();

        int version = request.getVersionNumber();
        if(requestOption.isVersionAllowed(version) == false)
        {
            String message = "invalid request version " + version;
            LOG.warn(message);
            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
            }
            return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
        }

        try
        {
            OcspRespWithCacheInfo resp = checkSignature(request, requestOption, auditEvent);
            if(resp != null)
            {
                return resp;
            }

            boolean couldCacheInfo = viaGet;

            List<Extension> responseExtensions = new ArrayList<>(2);

            Req[] requestList = request.getRequestList();
            int n = requestList.length;

            Set<ASN1ObjectIdentifier> criticalExtensionOIDs = new HashSet<>();
            Set<?> tmp = request.getCriticalExtensionOIDs();
            if(tmp != null)
            {
                for(Object oid : tmp)
                {
                    criticalExtensionOIDs.add((ASN1ObjectIdentifier) oid);
                }
            }

            RespID respID = new RespID(signer.getResponderId());
            BasicOCSPRespBuilder basicOcspBuilder = new BasicOCSPRespBuilder(respID);
            ASN1ObjectIdentifier extensionType = OCSPObjectIdentifiers.id_pkix_ocsp_nonce;
            criticalExtensionOIDs.remove(extensionType);
            Extension nonceExtn = request.getExtension(extensionType);
            if(nonceExtn != null)
            {
                byte[] nonce = nonceExtn.getExtnValue().getOctets();
                int len = nonce.length;
                int min = requestOption.getNonceMinLen();
                int max = requestOption.getNonceMaxLen();

                if(len < min || len > max)
                {
                    LOG.warn("length of nonce {} not within [{},{}]", new Object[]{len, min, max});
                    if(auditEvent != null)
                    {
                        StringBuilder sb = new StringBuilder();
                        sb.append("length of nonce ").append(len);
                        sb.append(" not within [").append(min).append(", ").append(max);
                        fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, sb.toString());
                    }
                    return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
                }

                couldCacheInfo = false;
                responseExtensions.add(nonceExtn);
            }
            else if(requestOption.isNonceRequired())
            {
                String message = "nonce required, but is not present in the request";
                LOG.warn(message);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
                }
                return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
            }

            boolean includeExtendedRevokeExtension = false;

            long cacheThisUpdate = 0;
            long cacheNextUpdate = Long.MAX_VALUE;
            for(int i = 0; i < n; i++)
            {
                AuditChildEvent childAuditEvent = null;
                if(auditEvent != null)
                {
                    childAuditEvent = new AuditChildEvent();
                    auditEvent.addChildAuditEvent(childAuditEvent);
                }

                Req req = requestList[i];
                CertificateID certID =  req.getCertID();
                String certIdHashAlgo = certID.getHashAlgOID().getId();
                HashAlgoType reqHashAlgo = HashAlgoType.getHashAlgoType(certIdHashAlgo);
                if(reqHashAlgo == null)
                {
                    LOG.warn("unknown CertID.hashAlgorithm {}", certIdHashAlgo);
                    if(childAuditEvent != null)
                    {
                        fillAuditEvent(childAuditEvent, AuditLevel.INFO, AuditStatus.FAILED,
                                "unknown CertID.hashAlgorithm " + certIdHashAlgo);
                    }
                    return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
                }
                else if(requestOption.allows(reqHashAlgo) == false)
                {
                    LOG.warn("CertID.hashAlgorithm {} not allowed", certIdHashAlgo);
                    if(childAuditEvent != null)
                    {
                        fillAuditEvent(childAuditEvent, AuditLevel.INFO, AuditStatus.FAILED,
                                "CertID.hashAlgorithm " + certIdHashAlgo + " not allowed");
                    }
                    return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
                }

                CertStatusInfo certStatusInfo = null;
                CertStatusStore answeredStore = null;
                boolean exceptionOccurs = false;

                for(CertStatusStore store : responder.getStores())
                {
                    try
                    {
                        certStatusInfo = store.getCertStatus(
                                reqHashAlgo, certID.getIssuerNameHash(), certID.getIssuerKeyHash(),
                                certID.getSerialNumber(), responseOption.isIncludeCerthash(),
                                responseOption.getCertHashAlgo(), certprofileOption);
                        if(certStatusInfo.getCertStatus() != CertStatus.ISSUER_UNKNOWN)
                        {
                            answeredStore = store;
                            break;
                        }
                    } catch (CertStatusStoreException e)
                    {
                        exceptionOccurs = true;
                        final String message = "getCertStatus() of CertStatusStore " + store.getName();
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                    }
                }

                if(certStatusInfo == null)
                {
                    if(childAuditEvent != null)
                    {
                        fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.FAILED,
                                "no CertStatusStore can answer the request");
                    }
                    if(exceptionOccurs)
                    {
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.tryLater);
                    }
                    else
                    {
                        certStatusInfo = CertStatusInfo.getIssuerUnknownCertStatusInfo(new Date(), null);
                    }
                } else if(answeredStore != null)
                {
                    if(responderOption.isInheritCaRevocation())
                    {
                        CertRevocationInfo caRevInfo = answeredStore.getCARevocationInfo(
                                reqHashAlgo, certID.getIssuerNameHash(), certID.getIssuerKeyHash());
                        if(caRevInfo != null)
                        {
                            CertStatus certStatus = certStatusInfo.getCertStatus();
                            boolean replaced = false;
                            if(certStatus == CertStatus.GOOD || certStatus == CertStatus.UNKNOWN)
                            {
                                replaced = true;
                            }
                            else if(certStatus == CertStatus.REVOKED)
                            {
                                if(certStatusInfo.getRevocationInfo().getRevocationTime().after(
                                        caRevInfo.getRevocationTime()))
                                {
                                    replaced = true;
                                }
                            }

                            if(replaced)
                            {
                                CertRevocationInfo newRevInfo;
                                if(caRevInfo.getReason() == CRLReason.CA_COMPROMISE)
                                {
                                    newRevInfo = caRevInfo;
                                }
                                else
                                {
                                    newRevInfo = new CertRevocationInfo(CRLReason.CA_COMPROMISE,
                                        caRevInfo.getRevocationTime(), caRevInfo.getInvalidityTime());
                                }
                                certStatusInfo = CertStatusInfo.getRevokedCertStatusInfo(newRevInfo,
                                        certStatusInfo.getCertHashAlgo(), certStatusInfo.getCertHash(),
                                        certStatusInfo.getThisUpdate(), certStatusInfo.getNextUpdate(),
                                        certStatusInfo.getCertprofile());
                            }
                        }
                    }
                }

                if(childAuditEvent != null)
                {
                    String certprofile = certStatusInfo.getCertprofile();
                    String auditCertType;
                    if(certprofile != null)
                    {
                        auditCertType = auditOption.getCertprofileMapping().get(certprofile);
                        if(auditCertType == null)
                        {
                            auditCertType = certprofile;
                        }
                    }
                    else
                    {
                        auditCertType = "UNKNOWN";
                    }

                    childAuditEvent.addEventData(new AuditEventData("certType", auditCertType));
                }

                // certStatusInfo could not be null in any case, since at least one store is configured
                Date thisUpdate = certStatusInfo.getThisUpdate();
                if(thisUpdate == null)
                {
                    thisUpdate = new Date();
                }
                Date nextUpdate = certStatusInfo.getNextUpdate();

                List<Extension> extensions = new LinkedList<>();
                boolean unknownAsRevoked = false;
                CertificateStatus bcCertStatus = null;
                switch(certStatusInfo.getCertStatus())
                {
                    case GOOD:
                        bcCertStatus = null;
                        break;

                    case ISSUER_UNKNOWN:
                        couldCacheInfo = false;
                        bcCertStatus = new UnknownStatus();
                        break;

                    case UNKNOWN:
                    case IGNORE:
                        couldCacheInfo = false;
                        if(responderOption.getMode() == OCSPMode.RFC2560)
                        {
                            bcCertStatus = new UnknownStatus();
                        }
                        else// (ocspMode == OCSPMode.RFC6960)
                        {
                            unknownAsRevoked = true;
                            includeExtendedRevokeExtension = true;
                            bcCertStatus = new RevokedStatus(new Date(0L),
                                    CRLReason.CERTIFICATE_HOLD.getCode());
                        }
                        break;
                    case REVOKED:
                        CertRevocationInfo revInfo = certStatusInfo.getRevocationInfo();
                        ASN1GeneralizedTime revTime = new ASN1GeneralizedTime(
                                revInfo.getRevocationTime());
                        org.bouncycastle.asn1.x509.CRLReason _reason = null;
                        if(responseOption.isIncludeRevReason())
                        {
                            _reason = org.bouncycastle.asn1.x509.CRLReason.lookup(
                                    revInfo.getReason().getCode());
                        }
                        RevokedInfo _revInfo = new RevokedInfo(revTime, _reason);
                        bcCertStatus = new RevokedStatus(_revInfo);

                        Date invalidityDate = revInfo.getInvalidityTime();
                        if(responseOption.isIncludeInvalidityDate()
                                && invalidityDate != null
                                && invalidityDate.equals(revTime) == false)
                        {
                            Extension extension = new Extension(Extension.invalidityDate,
                                    false, new ASN1GeneralizedTime(invalidityDate).getEncoded());
                            extensions.add(extension);
                        }
                        break;
                }

                byte[] certHash = certStatusInfo.getCertHash();
                if(certHash != null)
                {
                    ASN1ObjectIdentifier hashAlgoOid =
                            new ASN1ObjectIdentifier(certStatusInfo.getCertHashAlgo().getOid());
                    AlgorithmIdentifier aId =
                            new AlgorithmIdentifier(hashAlgoOid, DERNull.INSTANCE);
                    CertHash bcCertHash = new CertHash(aId, certHash);

                    byte[] encodedCertHash;
                    try
                    {
                        encodedCertHash = bcCertHash.getEncoded();
                    } catch (IOException e)
                    {
                        final String message = "answer() bcCertHash.getEncoded";
                        if(LOG.isErrorEnabled())
                        {
                            LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                        }
                        LOG.debug(message, e);
                        if(childAuditEvent != null)
                        {
                            fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.FAILED,
                                    "CertHash.getEncoded() with IOException");
                        }
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
                    }

                    Extension extension = new Extension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash,
                            false, encodedCertHash);

                    extensions.add(extension);
                }

                if(certStatusInfo.getArchiveCutOff() != null)
                {
                    Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff,
                            false, new ASN1GeneralizedTime(certStatusInfo.getArchiveCutOff()).getEncoded());
                    extensions.add(extension);
                }

                String certStatusText;
                if(bcCertStatus instanceof UnknownStatus)
                {
                    certStatusText = "unknown";
                }
                else if(bcCertStatus instanceof RevokedStatus)
                {
                    certStatusText = unknownAsRevoked
                            ? "unknown_as_revoked"
                            : "revoked";
                }
                else if(bcCertStatus == null)
                {
                    certStatusText = "good";
                }
                else
                {
                    certStatusText = "should-not-happen";
                }

                if(childAuditEvent != null)
                {
                    childAuditEvent.setLevel(AuditLevel.INFO);
                    childAuditEvent.setStatus(AuditStatus.SUCCESSFUL);
                    childAuditEvent.addEventData(new AuditEventData("certStatus", certStatusText));
                }

                if(LOG.isDebugEnabled())
                {
                    StringBuilder sb = new StringBuilder();
                    sb.append("certHashAlgo: ").append(certID.getHashAlgOID().getId()).append(", ");

                    String hexCertHash = null;
                    if(certHash != null)
                    {
                        hexCertHash = Hex.toHexString(certHash).toUpperCase();
                    }

                    sb.append("issuerKeyHash: ") .append(Hex.toHexString(
                            certID.getIssuerKeyHash()) .toUpperCase()).append(", ");
                    sb.append("issuerNameHash: ").append(Hex.toHexString(
                            certID.getIssuerNameHash()).toUpperCase()).append(", ");
                    sb.append("serialNumber: ").append(certID.getSerialNumber()).append(", ");
                    sb.append("certStatus: ").append(certStatusText).append(", ");
                    sb.append("thisUpdate: ").append(thisUpdate).append(", ");
                    sb.append("nextUpdate: ").append(nextUpdate).append(", ");
                    sb.append("certHash: ").append(hexCertHash);
                    LOG.debug(sb.toString());
                }

                Extensions extns = null;
                if(CollectionUtil.isNotEmpty(extensions))
                {
                    extns = new Extensions(extensions.toArray(new Extension[0]));
                }
                basicOcspBuilder.addResponse(certID, bcCertStatus, thisUpdate, nextUpdate, extns);
                cacheThisUpdate = Math.max(cacheThisUpdate, thisUpdate.getTime());
                if(nextUpdate != null)
                {
                    cacheNextUpdate = Math.min(cacheNextUpdate, nextUpdate.getTime());
                }
            }

            if(includeExtendedRevokeExtension)
            {
                responseExtensions.add(
                        new Extension(ObjectIdentifiers.id_pkix_ocsp_extendedRevoke, true, DERNull.INSTANCE.getEncoded()));
            }

            if(CollectionUtil.isNotEmpty(responseExtensions))
            {
                basicOcspBuilder.setResponseExtensions(
                        new Extensions(responseExtensions.toArray(new Extension[0])));
            }

            ConcurrentContentSigner concurrentSigner = null;
            if(responderOption.getMode() != OCSPMode.RFC2560)
            {
                extensionType = ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs;
                criticalExtensionOIDs.remove(extensionType);
                Extension ext = request.getExtension(extensionType);
                if(ext != null)
                {
                    ASN1Sequence preferredSigAlgs = ASN1Sequence.getInstance(ext.getParsedValue());
                    concurrentSigner = signer.getSignerForPreferredSigAlgs(preferredSigAlgs);
                }
            }

            if(CollectionUtil.isNotEmpty(criticalExtensionOIDs))
            {
                return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
            }

            if(concurrentSigner == null)
            {
                concurrentSigner = signer.getFirstSigner();
            }

            ContentSigner singleSigner;
            try
            {
                singleSigner = concurrentSigner.borrowContentSigner();
            }catch(NoIdleSignerException e)
            {
                return createUnsuccessfullOCSPResp(OcspResponseStatus.tryLater);
            }

            X509CertificateHolder[] certsInResp;
            EmbedCertsMode certsMode = responseOption.getEmbedCertsMode();
            if(certsMode == null || certsMode == EmbedCertsMode.SIGNER)
            {
                certsInResp = new X509CertificateHolder[]{signer.getBcCertificate()};
            }
            else if(certsMode == EmbedCertsMode.SIGNER_AND_CA)
            {
                certsInResp = signer.getBcCertificateChain();
            }
            else
            {
                // NONE
                certsInResp = null;
            }

            BasicOCSPResp basicOcspResp;
            try
            {
                basicOcspResp = basicOcspBuilder.build(singleSigner, certsInResp, new Date());
            } catch (OCSPException e)
            {
                final String message = "answer() basicOcspBuilder.build";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.FAILED,
                            "BasicOCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
            } finally
            {
                concurrentSigner.returnContentSigner(singleSigner);
            }

            OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
            try
            {
                OCSPResp ocspResp = ocspRespBuilder.build(OcspResponseStatus.successfull.getStatus(), basicOcspResp);

                if(couldCacheInfo)
                {
                    ResponseCacheInfo cacheInfo = new ResponseCacheInfo(cacheThisUpdate);
                    if(cacheNextUpdate != Long.MAX_VALUE)
                    {
                        cacheInfo.setNextUpdate(cacheNextUpdate);
                    }
                    return new OcspRespWithCacheInfo(ocspResp, cacheInfo);
                }
                else
                {
                    return new OcspRespWithCacheInfo(ocspResp, null);
                }
            } catch (OCSPException e)
            {
                final String message = "answer() ocspRespBuilder.build";
                if(LOG.isErrorEnabled())
                {
                    LOG.error(LogUtil.buildExceptionLogFormat(message), e.getClass().getName(), e.getMessage());
                }
                LOG.debug(message, e);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.FAILED,
                            "OCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
            }

        }catch(Throwable t)
        {
            final String message = "Throwable";
            if(LOG.isErrorEnabled())
            {
                LOG.error(LogUtil.buildExceptionLogFormat(message), t.getClass().getName(), t.getMessage());
            }
            LOG.debug(message, t);

            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.FAILED,
                        "internal error");
            }

            return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
        }
    }

    private static OcspRespWithCacheInfo createUnsuccessfullOCSPResp(
            final OcspResponseStatus status)
    {
        OCSPResp resp = new OCSPResp(new OCSPResponse(
                new org.bouncycastle.asn1.ocsp.OCSPResponseStatus(status.getStatus()), null));
        return new OcspRespWithCacheInfo(resp, null);
    }

    public HealthCheckResult healthCheck(
            final Responder responder)
    {
        HealthCheckResult result = new HealthCheckResult("OCSPResponder");
        boolean healthy = true;

        for(CertStatusStore store : responder.getStores())
        {
            boolean storeHealthy = store.isHealthy();
            healthy &= storeHealthy;

            HealthCheckResult storeHealth = new HealthCheckResult("CertStatusStore." + store.getName());
            storeHealth.setHealthy(storeHealthy);
            result.addChildCheck(storeHealth);
        }

        boolean signerHealthy = responder.getSigner().isHealthy();
        healthy &= signerHealthy;

        HealthCheckResult signerHealth = new HealthCheckResult("Signer");
        signerHealth.setHealthy(signerHealthy);
        result.addChildCheck(signerHealth);

        result.setHealthy(healthy);
        return result;
    }

    private static void fillAuditEvent(
            final AuditEvent auditEvent,
            final AuditLevel level,
            final AuditStatus status,
            final String message)
    {
        if(level != null)
        {
            auditEvent.setLevel(level);
        }

        if(status != null)
        {
            auditEvent.setStatus(status);
        }

        if(message != null)
        {
            auditEvent.addEventData(new AuditEventData("messsage", message));
        }
    }

    private static void fillAuditEvent(
            final AuditChildEvent auditEvent,
            final AuditLevel level,
            final AuditStatus status,
            final String message)
    {
        if(level != null)
        {
            auditEvent.setLevel(level);
        }

        if(status != null)
        {
            auditEvent.setStatus(status);
        }

        if(message != null)
        {
            auditEvent.addEventData(new AuditEventData("messsage", message));
        }
    }

    public void setAuditServiceRegister(
            final AuditServiceRegister auditServiceRegister)
    {
        this.auditServiceRegister = auditServiceRegister;
        for(CertStatusStore store : stores.values())
        {
            store.setAuditServiceRegister(auditServiceRegister);
        }
    }

    private void auditLogPCIEvent(
            final boolean successfull,
            final String eventType)
    {
        AuditService auditService = (auditServiceRegister == null)
                ? null
                : auditServiceRegister.getAuditService();
        if(auditService != null)
        {
            PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
            auditEvent.setUserId("OCSP-SYSTEM");
            auditEvent.setEventType(eventType);
            auditEvent.setAffectedResource("CORE");
            if(successfull)
            {
                auditEvent.setStatus(AuditStatus.SUCCESSFUL.name());
                auditEvent.setLevel(AuditLevel.INFO);
            }
            else
            {
                auditEvent.setStatus(AuditStatus.FAILED.name());
                auditEvent.setLevel(AuditLevel.ERROR);
            }
            auditService.logEvent(auditEvent);
        }
    }

    private ResponderSigner initSigner(
            final SignerType m)
    throws InvalidConfException
    {
        X509Certificate[] explicitCertificateChain = null;

        X509Certificate explicitResponderCert = null;
        if(m.getCert() != null)
        {
            explicitResponderCert = parseCert(m.getCert());
        }

        if(explicitResponderCert != null)
        {
            Set<X509Certificate> caCerts = null;
            if(m.getCaCerts() != null)
            {
                caCerts = new HashSet<>();

                for(FileOrValueType certConf : m.getCaCerts().getCaCert())
                {
                    caCerts.add(parseCert(certConf));
                }
            }

            explicitCertificateChain = X509Util.buildCertPath(explicitResponderCert, caCerts);
        }

        String responderSignerType = m.getType();
        String responderKeyConf = m.getKey();

        List<String> sigAlgos = m.getAlgorithms().getAlgorithm();
        List<ConcurrentContentSigner> singleSigners = new ArrayList<>(sigAlgos.size());
        for(String sigAlgo : sigAlgos)
        {
            try
            {
                ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                        responderSignerType, "algo" +ConfPairs.NAME_TERM + sigAlgo + ConfPairs.TOKEN_TERM + responderKeyConf,
                        explicitCertificateChain);
                singleSigners.add(requestorSigner);
            } catch (SignerException e)
            {
                throw new InvalidConfException("SignerException: " + e.getMessage(), e);
            }
        }

        try
        {
            return new ResponderSigner(singleSigners);
        } catch (CertificateEncodingException | IOException e)
        {
            throw new InvalidConfException(e.getMessage(), e);
        }
    }

    private CertStatusStore initStore(
            final StoreType conf,
            final Map<String, DataSourceWrapper> datasources)
    throws InvalidConfException
    {
        String name = conf.getName();

        String statusStoreConf = null;
        String datasourceName = null;

        Source source = conf.getSource();
        CertStatusStore store;
        if(source.getDbStore() != null)
        {
            DbStoreType dbStoreConf = source.getDbStore();
            datasourceName = dbStoreConf.getDatasource();

            IssuerFilter issuerFilter;
            try
            {
                Set<X509Certificate> includeIssuers = null;
                Set<X509Certificate> excludeIssuers = null;

                if(dbStoreConf.getCacerts() != null)
                {
                    IncludesFileOrValueType includes = dbStoreConf.getCacerts().getIncludes();
                    if(includes != null)
                    {
                        includeIssuers = parseCerts(includes.getInclude());
                    }

                    ExcludesFileOrValueType excludes = dbStoreConf.getCacerts().getExcludes();
                    if(excludes != null)
                    {
                        excludeIssuers = parseCerts(excludes.getExclude());
                    }
                }

                issuerFilter = new IssuerFilter(includeIssuers, excludeIssuers);
            } catch (CertificateException e)
            {
                throw new InvalidConfException(e.getMessage(), e);
            }
            store = new DbCertStatusStore(name, issuerFilter);

            Integer i = conf.getRetentionInterval();
            int retentionInterva = (i == null)
                    ? -1
                    : i.intValue();
            store.setRetentionInterval(retentionInterva);
            store.setUnknownSerialAsGood(
                    getBoolean(conf.isUnknownSerialAsGood(), false));
        }
        else if(source.getCrlStore() != null)
        {
            CrlStoreType crlStoreConf = source.getCrlStore();
            X509Certificate caCert = parseCert(crlStoreConf.getCaCert());
            X509Certificate crlIssuerCert = null;
            if(crlStoreConf.getIssuerCert() != null)
            {
                crlIssuerCert = parseCert(crlStoreConf.getIssuerCert());
            }

            CrlCertStatusStore crlStore = new CrlCertStatusStore(name,
                    crlStoreConf.getCrlFile(), crlStoreConf.getDeltaCrlFile(),
                    caCert, crlIssuerCert, crlStoreConf.getCrlUrl(),
                    crlStoreConf.getCertsDir());
            store = crlStore;

            crlStore.setUseUpdateDatesFromCRL(
                    getBoolean(crlStoreConf.isUseUpdateDatesFromCRL(), true));
            boolean caRevoked = getBoolean(crlStoreConf.isCaRevoked(), false);
            if(caRevoked)
            {
                XMLGregorianCalendar caRevTime = crlStoreConf.getCaRevocationTime();
                if(caRevTime == null)
                {
                    throw new InvalidConfException("caRevocationTime is not specified");
                }
                crlStore.setCARevocationInfo(caRevTime.toGregorianCalendar().getTime());
            }

            Integer i = conf.getRetentionInterval();
            int retentionInterval = (i == null)
                    ? 0
                    : i.intValue();
            store.setRetentionInterval(retentionInterval);
            store.setUnknownSerialAsGood(
                    getBoolean(conf.isUnknownSerialAsGood(), true));
        }
        else if(source.getCustomStore() != null)
        {
            CustomStoreType customStoreConf = source.getCustomStore();
            String className = customStoreConf.getClassName();
            statusStoreConf = customStoreConf.getConf();
            datasourceName = customStoreConf.getDatasource();

            Object instance;
            try
            {
                Class<?> clazz = Class.forName(className);
                instance = clazz.newInstance();
            }catch(Exception e)
            {
                throw new InvalidConfException(e.getMessage(), e);
            }

            if(instance instanceof CertStatusStore)
            {
                store = (CertStatusStore) instance;
            }
            {
                throw new InvalidConfException(className + " is not instanceof " + CertStatusStore.class.getName());
            }
        }
        else
        {
            throw new RuntimeException("should not reach here, unknwon CertStore type");
        }

        store.setIncludeArchiveCutoff(
                getBoolean(conf.isIncludeArchiveCutoff(), true));
        store.setIncludeCrlID(
                getBoolean(conf.isIncludeCrlID(), true));

        DataSourceWrapper datasource = null;
        if(datasourceName != null)
        {
            datasource = datasources.get(datasourceName);
            if(datasource == null)
            {
                throw new InvalidConfException("datasource named '" + datasourceName + "'  not definied");
            }
        }
        try
        {
            store.init(statusStoreConf, datasource);
        }catch(CertStatusStoreException e)
        {
            throw new InvalidConfException("CertStatusStoreException of store " + conf.getName()
                    + ":" + e.getMessage(), e);
        }

        return store;
    }

    private OcspRespWithCacheInfo checkSignature(
            final OCSPReq request,
            final RequestOption requestOption,
            final AuditEvent auditEvent)
    throws OCSPException, CertificateParsingException, InvalidAlgorithmParameterException, OcspResponderException
    {
        if(request.isSigned() == false)
        {
            if(requestOption.isSignatureRequired() == false)
            {
                return null;
            }

            String message = "signature in request required";
            LOG.warn(message);
            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
            }
            return createUnsuccessfullOCSPResp(OcspResponseStatus.sigRequired);
        }

        if(requestOption.isValidateSignature() == false)
        {
            return null;
        }

        X509CertificateHolder[] certs = request.getCerts();
        if(certs == null || certs.length < 1)
        {
            String message = "no certificate found in request to verify the signature";
            LOG.warn(message);
            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
            }
            return createUnsuccessfullOCSPResp(OcspResponseStatus.unauthorized);
        }

        ContentVerifierProvider cvp;
        try
        {
            cvp = securityFactory.getContentVerifierProvider(certs[0]);
        }catch(InvalidKeyException e)
        {
            LOG.warn("securityFactory.getContentVerifierProvider, InvalidKeyException: {}", e.getMessage());
            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.FAILED, e.getMessage());
            }
            return createUnsuccessfullOCSPResp(OcspResponseStatus.unauthorized);
        }

        boolean sigValid = request.isSignatureValid(cvp);
        if(sigValid == false)
        {
            String message = "request signature is invalid";
            LOG.warn(message);
            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
            }
            return createUnsuccessfullOCSPResp(OcspResponseStatus.unauthorized);
        }

        // validate the certPath
        Date referenceTime = new Date();
        if(canBuildCertpath(certs, requestOption, referenceTime))
        {
            return null;
        }

        String message = "could not build certpath for the request's signer certifcate";
        LOG.warn(message);
        if(auditEvent != null)
        {
            fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
        }
        return createUnsuccessfullOCSPResp(OcspResponseStatus.unauthorized);
    }

    private static boolean canBuildCertpath(
            final X509CertificateHolder[] certsInReq,
            final RequestOption requestOption,
            final Date referenceTime)
    {
        X509Certificate target;
        try
        {
            target = new X509CertificateObject(certsInReq[0].toASN1Structure());
        } catch (CertificateParsingException e)
        {
            return false;
        }

        Set<Certificate> certstore = new HashSet<>();

        Set<CertWithEncoded> trustAnchors = requestOption.getTrustAnchors();
        for(CertWithEncoded m : trustAnchors)
        {
            certstore.add(m.getCertificate());
        }

        final int n = certsInReq.length;
        if(n > 1)
        {
            for(int i = 1; i < n; i++)
            {
                Certificate c;
                try
                {
                    c = new X509CertificateObject(certsInReq[i].toASN1Structure());
                } catch (CertificateParsingException e)
                {
                    continue;
                }
                certstore.add(c);
            }
        }

        Set<X509Certificate> configuredCerts = requestOption.getCerts();
        if(CollectionUtil.isNotEmpty(configuredCerts))
        {
            certstore.addAll(requestOption.getCerts());
        }

        X509Certificate[] certpath = X509Util.buildCertPath(target, certstore);
        CertpathValidationModel model = requestOption.getCertpathValidationModel();

        Date now = new Date();
        if(model == null || model == CertpathValidationModel.PKIX )
        {
            for(X509Certificate m : certpath)
            {
                if(m.getNotBefore().after(now) || m.getNotAfter().before(now))
                {
                    return false;
                }
            }
        }
        else if(model == CertpathValidationModel.CHAIN)
        {
            // do nothing
        }
        else
        {
            throw new RuntimeException("invalid CertpathValidationModel " + model.name());
        }

        for(int i = certpath.length - 1; i >= 0; i--)
        {
            X509Certificate targetCert = certpath[i];
            for(CertWithEncoded m : trustAnchors)
            {
                if(m.equalsCert(targetCert))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean getBoolean(
            final Boolean b,
            final boolean defaultValue)
    {
        return (b == null)
                ? defaultValue
                : b.booleanValue();
    }

    private static Set<X509Certificate> parseCerts(
            final List<FileOrValueType> certConfs)
    throws InvalidConfException
    {
        Set<X509Certificate> certs = new HashSet<>(certConfs.size());
        for(FileOrValueType m : certConfs)
        {
            certs.add(parseCert(m));
        }
        return certs;
    }

    private static InputStream getInputStream(
            final FileOrValueType conf)
    throws IOException
    {
        if(conf.getFile() != null)
        {
            return new FileInputStream(IoUtil.expandFilepath(conf.getFile()));
        }
        else
        {
            return new ByteArrayInputStream(conf.getValue());
        }
    }

    private static InputStream getInputStream(
            final FileOrPlainValueType conf)
    throws IOException
    {
        if(conf.getFile() != null)
        {
            return new FileInputStream(IoUtil.expandFilepath(conf.getFile()));
        }
        else
        {
            return new ByteArrayInputStream(conf.getValue().getBytes());
        }
    }

    private static void close(
            final InputStream stream)
    {
        if(stream != null)
        {
            try
            {
                stream.close();
            }catch(IOException e)
            {
            }
        }
    }

    private static X509Certificate parseCert(
            final FileOrValueType certConf)
    throws InvalidConfException
    {
        InputStream is = null;
        try
        {
            is = getInputStream(certConf);
            return X509Util.parseCert(is);
        } catch (IOException | CertificateException e)
        {
            String msg = "could not parse certificate";
            if(certConf.getFile() != null)
            {
                msg += " from file " + certConf.getFile();
            }
            throw new InvalidConfException(msg);
        }finally
        {
            close(is);
        }
    }

    private static OCSPServer parseConf(
            final String confFilename)
    throws InvalidConfException
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            SchemaFactory schemaFact = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFact.newSchema(OcspServer.class.getResource("/xsd/ocsp-conf.xsd"));
            unmarshaller.setSchema(schema);
            return (OCSPServer) unmarshaller.unmarshal(new File(IoUtil.expandFilepath(confFilename)));
        } catch(SAXException e)
        {
            throw new InvalidConfException("parse profile failed, message: " + e.getMessage(), e);
        } catch(JAXBException e)
        {
            throw new InvalidConfException("parse profile failed, message: " + XMLUtil.getMessage((JAXBException) e), e);
        }
    }

    public static void main(
            final String[] args)
    {
        String confFile = "../../dist/pki/assembly/src/main/unfiltered/xipki/ocsp-config/ocsp-responder.xml";
        try
        {
            parseConf(confFile);
        }catch(Exception e)
        {
            System.err.println(e.getMessage());
        }
    }
}
