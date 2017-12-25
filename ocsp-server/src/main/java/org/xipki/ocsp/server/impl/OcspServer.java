/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ocsp.server.impl;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.HealthCheckResult;
import org.xipki.common.InvalidConfException;
import org.xipki.common.ObjectCreationException;
import org.xipki.common.TripleState;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.common.util.XmlUtil;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.datasource.springframework.dao.DataAccessException;
import org.xipki.http.servlet.ServletURI;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.OcspMode;
import org.xipki.ocsp.api.OcspStore;
import org.xipki.ocsp.api.OcspStoreException;
import org.xipki.ocsp.api.OcspStoreFactoryRegister;
import org.xipki.ocsp.server.impl.OcspRespWithCacheInfo.ResponseCacheInfo;
import org.xipki.ocsp.server.impl.jaxb.DatasourceType;
import org.xipki.ocsp.server.impl.jaxb.EmbedCertsMode;
import org.xipki.ocsp.server.impl.jaxb.FileOrPlainValueType;
import org.xipki.ocsp.server.impl.jaxb.FileOrValueType;
import org.xipki.ocsp.server.impl.jaxb.OCSPServer;
import org.xipki.ocsp.server.impl.jaxb.ObjectFactory;
import org.xipki.ocsp.server.impl.jaxb.RequestOptionType;
import org.xipki.ocsp.server.impl.jaxb.ResponderType;
import org.xipki.ocsp.server.impl.jaxb.ResponseCacheType;
import org.xipki.ocsp.server.impl.jaxb.ResponseOptionType;
import org.xipki.ocsp.server.impl.jaxb.SignerType;
import org.xipki.ocsp.server.impl.jaxb.StoreType;
import org.xipki.ocsp.server.impl.store.crl.CrlDbCertStatusStore;
import org.xipki.ocsp.server.impl.store.db.DbCertStatusStore;
import org.xipki.ocsp.server.impl.type.CertID;
import org.xipki.ocsp.server.impl.type.EncodingException;
import org.xipki.ocsp.server.impl.type.ExtendedExtension;
import org.xipki.ocsp.server.impl.type.Extension;
import org.xipki.ocsp.server.impl.type.Extensions;
import org.xipki.ocsp.server.impl.type.OID;
import org.xipki.ocsp.server.impl.type.OcspRequest;
import org.xipki.ocsp.server.impl.type.ResponderID;
import org.xipki.ocsp.server.impl.type.TaggedCertSequence;
import org.xipki.ocsp.server.impl.type.WritableOnlyExtension;
import org.xipki.password.PasswordResolverException;
import org.xipki.security.AlgorithmCode;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CertpathValidationModel;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.HashAlgoType;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignerConf;
import org.xipki.security.exception.NoIdleSignerException;
import org.xipki.security.util.X509Util;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class OcspServer {

    private static class SizeComparableString implements Comparable<SizeComparableString> {

        private String str;

        public SizeComparableString(String str) {
            this.str = ParamUtil.requireNonNull("str", str);
        }

        @Override
        public int compareTo(SizeComparableString obj) {
            if (str.length() == obj.str.length()) {
                return 0;
            }

            return (str.length() > obj.str.length()) ? 1 : -1;
        }

    }

    private static class OcspRespControl {
        boolean canCacheInfo;
        boolean includeExtendedRevokeExtension;
        long cacheThisUpdate;
        long cacheNextUpdate;

        public OcspRespControl() {
            includeExtendedRevokeExtension = false;
            cacheThisUpdate = 0;
            cacheNextUpdate = Long.MAX_VALUE;
        }
    }

    public static final long DFLT_CACHE_MAX_AGE = 60; // 1 minute

    private static final byte[] DERNullBytes = new byte[]{0x05, 0x00};

    private static final byte[] bytes_certstatus_good = new byte[]{(byte) 0x80, 0x00};

    private static final byte[] bytes_certstatus_unknown = new byte[]{(byte) 0x82, 0x00};

    private static final byte[] bytes_certstatus_rfc6960_unknown =
            Hex.decode("a116180f31393730303130313030303030305aa0030a0106");

    private static final WritableOnlyExtension extension_pkix_ocsp_extendedRevoke;

    private static final Logger LOG = LoggerFactory.getLogger(OcspServer.class);

    private static final Map<OcspResponseStatus, OcspRespWithCacheInfo> unsuccesfulOCSPRespMap;

    private final DataSourceFactory datasourceFactory;

    private SecurityFactory securityFactory;

    private String confFile;

    private boolean master;

    private ResponseCacher responseCacher;

    private OcspStoreFactoryRegister ocspStoreFactoryRegister;

    private Map<String, Responder> responders = new HashMap<>();

    private Map<String, ResponderSigner> signers = new HashMap<>();

    private Map<String, RequestOption> requestOptions = new HashMap<>();

    private Map<String, ResponseOption> responseOptions = new HashMap<>();

    private Map<String, OcspStore> stores = new HashMap<>();

    private List<String> servletPaths = new ArrayList<>();

    private Map<String, Responder> path2responderMap = new HashMap<>();

    private AtomicBoolean initialized = new AtomicBoolean(false);

    static {
        unsuccesfulOCSPRespMap = new HashMap<>(10);
        for (OcspResponseStatus status : OcspResponseStatus.values()) {
            if (status == OcspResponseStatus.successful) {
                continue;
            }
            OCSPResponse resp = new OCSPResponse(
                    new org.bouncycastle.asn1.ocsp.OCSPResponseStatus(status.status()), null);
            byte[] encoded;
            try {
                encoded = resp.getEncoded();
            } catch (IOException ex) {
                throw new ExceptionInInitializerError(
                        "could not encode OCSPResp for status " + status + ": " + ex.getMessage());
            }
            unsuccesfulOCSPRespMap.put(status, new OcspRespWithCacheInfo(encoded, null));
        }

        ExtendedExtension ext = new ExtendedExtension(OID.ID_PKIX_OCSP_EXTENDEDREVOKE,
                true, DERNullBytes);
        byte[] encoded = new byte[ext.encodedLength()];
        ext.write(encoded, 0);
        extension_pkix_ocsp_extendedRevoke = new WritableOnlyExtension(encoded);
    }

    public OcspServer() {
        this.datasourceFactory = new DataSourceFactory();
    }

    public void setSecurityFactory(final SecurityFactory securityFactory) {
        this.securityFactory = securityFactory;
    }

    public void setConfFile(final String confFile) {
        this.confFile = confFile;
    }

    Responder getResponder(final ServletURI servletUri) throws UnsupportedEncodingException {
        String path = servletUri.path();
        for (String servletPath : servletPaths) {
            if (path.startsWith(servletPath)) {
                return path2responderMap.get(servletPath);
            }
        }
        return null;
    }

    Object[] getServletPathAndResponder(final ServletURI servletUri)
            throws UnsupportedEncodingException {
        String path = servletUri.path();
        for (String servletPath : servletPaths) {
            if (path.startsWith(servletPath)) {
                return new Object[]{servletPath, path2responderMap.get(servletPath)};
            }
        }
        return null;
    }

    public Responder getResponder(final String name) {
        ParamUtil.requireNonBlank("name", name);
        return responders.get(name);
    }

    public boolean isInitialized() {
        return initialized.get();
    }

    public void init() throws InvalidConfException, PasswordResolverException, DataAccessException {
        LOG.info("starting OCSPResponder server ...");
        if (initialized.get()) {
            LOG.info("already started, skipping ...");
            return;
        }

        try {
            init0();
            initialized.set(true);
        } finally {
            if (initialized.get()) {
                LOG.info("started OCSPResponder server");
            } else {
                LOG.error("could not start OCSPResponder server");
            }
        }
    }

    private void init0()
            throws InvalidConfException, DataAccessException, PasswordResolverException {
        if (confFile == null) {
            throw new IllegalStateException("confFile is not set");
        }
        if (datasourceFactory == null) {
            throw new IllegalStateException("datasourceFactory is not set");
        }
        if (securityFactory == null) {
            throw new IllegalStateException("securityFactory is not set");
        }

        OCSPServer conf = parseConf(confFile);

        //-- check the duplication names
        Set<String> set = new HashSet<>();

        // Duplication name check: responder
        for (ResponderType m : conf.getResponders().getResponder()) {
            String name = m.getName();
            if (set.contains(name)) {
                throw new InvalidConfException(
                        "duplicated definition of responder named '" + name + "'");
            }

            if (StringUtil.isBlank(name)) {
                throw new InvalidConfException("responder name must not be empty");
            }

            for (int i = 0; i < name.length(); i++) {
                char ch = name.charAt(i);
                if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z'))) {
                    throw new InvalidConfException("invalid OCSP responder name '" + name + "'");
                }
            } // end for
            set.add(name);
        } // end for

        // Duplication name check: signer
        set.clear();
        for (SignerType m : conf.getSigners().getSigner()) {
            String name = m.getName();
            if (set.contains(name)) {
                throw new InvalidConfException(
                        "duplicated definition of signer option named '" + name + "'");
            }
            set.add(name);
        }

        // Duplication name check: requests
        set.clear();
        for (RequestOptionType m : conf.getRequestOptions().getRequestOption()) {
            String name = m.getName();
            if (set.contains(name)) {
                throw new InvalidConfException(
                        "duplicated definition of request option named '" + name + "'");
            }
            set.add(name);
        }

        // Duplication name check: response
        set.clear();
        for (ResponseOptionType m : conf.getResponseOptions().getResponseOption()) {
            String name = m.getName();
            if (set.contains(name)) {
                throw new InvalidConfException(
                        "duplicated definition of response option named '" + name + "'");
            }
            set.add(name);
        }

        // Duplication name check: store
        set.clear();
        for (StoreType m : conf.getStores().getStore()) {
            String name = m.getName();
            if (set.contains(name)) {
                throw new InvalidConfException(
                        "duplicated definition of store named '" + name + "'");
            }
        }

        // Duplication name check: datasource
        set.clear();
        if (conf.getDatasources() != null) {
            for (DatasourceType m : conf.getDatasources().getDatasource()) {
                String name = m.getName();
                if (set.contains(name)) {
                    throw new InvalidConfException(
                            "duplicated definition of datasource named '" + name + "'");
                }
                set.add(name);
            }
        }

        this.master = conf.isMaster();

        // Response Cache
        ResponseCacheType cacheType = conf.getResponseCache();
        if (cacheType != null) {
            DatasourceType cacheSourceConf = cacheType.getDatasource();
            DataSourceWrapper datasource;
            InputStream dsStream = null;
            try {
                dsStream = getInputStream(cacheSourceConf.getConf());
                datasource = datasourceFactory.createDataSource(cacheSourceConf.getName(),
                                dsStream, securityFactory.getPasswordResolver());
            } catch (IOException ex) {
                throw new InvalidConfException(ex.getMessage(), ex);
            } finally {
                close(dsStream);
            }
            responseCacher = new ResponseCacher(datasource, master, cacheType.getValidity());
            responseCacher.init();
        }

        //-- initializes the responders
        // signers
        for (SignerType m : conf.getSigners().getSigner()) {
            ResponderSigner signer = initSigner(m);
            signers.put(m.getName(), signer);
        }

        // requests
        for (RequestOptionType m : conf.getRequestOptions().getRequestOption()) {
            RequestOption option = new RequestOption(m);
            requestOptions.put(m.getName(), option);
        }

        // responses
        for (ResponseOptionType m : conf.getResponseOptions().getResponseOption()) {
            ResponseOption option = new ResponseOption(m);
            responseOptions.put(m.getName(), option);
        }

        // datasources
        Map<String, DataSourceWrapper> datasources = new HashMap<>();
        if (conf.getDatasources() != null) {
            for (DatasourceType m : conf.getDatasources().getDatasource()) {
                String name = m.getName();
                DataSourceWrapper datasource;
                InputStream dsStream = null;
                try {
                    dsStream = getInputStream(m.getConf());
                    datasource = datasourceFactory.createDataSource(name,
                                    dsStream, securityFactory.getPasswordResolver());
                } catch (IOException ex) {
                    throw new InvalidConfException(ex.getMessage(), ex);
                } finally {
                    close(dsStream);
                }
                datasources.put(name, datasource);
            } // end for
        } // end if

        // responders
        Map<String, ResponderOption> responderOptions = new HashMap<>();

        for (ResponderType m : conf.getResponders().getResponder()) {
            ResponderOption option = new ResponderOption(m);

            String optName = option.signerName();
            if (!signers.containsKey(optName)) {
                throw new InvalidConfException("no signer named '" + optName + "' is defined");
            }

            String reqOptName = option.requestOptionName();
            if (!requestOptions.containsKey(reqOptName)) {
                throw new InvalidConfException(
                        "no requestOption named '" + reqOptName + "' is defined");
            }

            String respOptName = option.responseOptionName();
            if (!responseOptions.containsKey(respOptName)) {
                throw new InvalidConfException(
                        "no responseOption named '" + respOptName + "' is defined");
            }

            // required HashAlgorithms for certificate
            ResponseOption respOpt = responseOptions.get(respOptName);
            Set<HashAlgoType> certHashAlgos = new HashSet<>(5);
            if (respOpt.isIncludeCerthash()) {
                if (respOpt.certHashAlgo() != null) {
                    certHashAlgos.add(respOpt.certHashAlgo());
                } else {
                    RequestOption reqOpt = requestOptions.get(reqOptName);
                    Set<HashAlgoType> algs = reqOpt.hashAlgos();
                    if (!CollectionUtil.isEmpty(algs)) {
                        certHashAlgos.addAll(algs);
                    } else {
                        HashAlgoType[] hashAlgos = new HashAlgoType[]{HashAlgoType.SHA1,
                            HashAlgoType.SHA224, HashAlgoType.SHA256, HashAlgoType.SHA384,
                            HashAlgoType.SHA512};
                        for (HashAlgoType hashAlgo : hashAlgos) {
                            certHashAlgos.add(hashAlgo);
                        }
                    }
                }
            }

            List<StoreType> storeDefs = conf.getStores().getStore();
            Set<String> storeNames = new HashSet<>(storeDefs.size());
            for (StoreType storeDef : storeDefs) {
                storeNames.add(storeDef.getName());
            }

            responderOptions.put(m.getName(), option);
        } // end for

        // stores
        for (StoreType m : conf.getStores().getStore()) {
            OcspStore store = newStore(m, datasources);
            stores.put(m.getName(), store);
        }

        // responders
        for (String name : responderOptions.keySet()) {
            ResponderOption option = responderOptions.get(name);

            List<OcspStore> statusStores = new ArrayList<>(option.storeNames().size());
            for (String storeName : option.storeNames()) {
                statusStores.add(stores.get(storeName));
            }

            ResponseOption responseOption = responseOptions.get(option.responseOptionName());
            ResponderSigner signer = signers.get(option.signerName());
            if (signer.isMacSigner()) {
                if (responseOption.isResponderIdByName()) {
                    throw new InvalidConfException(
                            "could not use ResponderIdByName for signer "
                            + option.signerName());
                }

                if (EmbedCertsMode.NONE != responseOption.embedCertsMode()) {
                    throw new InvalidConfException(
                            "could not embed certifcate in response for signer "
                            + option.signerName());
                }
            }

            Responder responder = new Responder(option,
                    requestOptions.get(option.requestOptionName()),
                    responseOption, signer, statusStores);
            responders.put(name, responder);
        } // end for

        // servlet paths
        List<SizeComparableString> tmpList = new LinkedList<>();
        for (String name : responderOptions.keySet()) {
            Responder responder = responders.get(name);
            ResponderOption option = responderOptions.get(name);
            List<String> strs = option.servletPaths();
            for (String path : strs) {
                tmpList.add(new SizeComparableString(path));
                path2responderMap.put(path, responder);
            }
        }

        // Sort the servlet paths according to the length of path. The first one is the
        // longest, and the last one is the shortest.
        Collections.sort(tmpList);
        List<String> list2 = new ArrayList<>(tmpList.size());
        for (SizeComparableString m : tmpList) {
            list2.add(m.str);
        }
        this.servletPaths = list2;
    } // method init0

    public void shutdown() {
        LOG.info("stopped OCSP Responder");
        if (responseCacher != null) {
            responseCacher.shutdown();
        }

        for (OcspStore store : stores.values()) {
            try {
                store.shutdown();
            } catch (Exception ex) {
                LogUtil.warn(LOG, ex, "shutdown store " + store.name());
            }
        }
    }

    public OcspRespWithCacheInfo answer(final Responder responder, final byte[] request,
            final boolean viaGet) {
        RequestOption reqOpt = responder.requestOption();

        int version;
        try {
            version = OcspRequest.readRequestVersion(request);
        } catch (EncodingException ex) {
            String message = "could not extract version from request";
            LOG.warn(message);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        if (!reqOpt.isVersionAllowed(version)) {
            String message = "invalid request version " + version;
            LOG.warn(message);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        ResponderSigner signer = responder.signer();
        ResponseOption repOpt = responder.responseOption();

        try {
            Object reqOrRrrorResp = checkSignature(request, reqOpt);
            if (reqOrRrrorResp instanceof OcspRespWithCacheInfo) {
                return (OcspRespWithCacheInfo) reqOrRrrorResp;
            }

            OcspRequest req = (OcspRequest) reqOrRrrorResp;

            List<CertID> requestList = req.requestList();
            int requestsSize = requestList.size();
            if (requestsSize > reqOpt.maxRequestListCount()) {
                String message = requestsSize + " entries in RequestList, but maximal "
                        + reqOpt.maxRequestListCount() + " is allowed";
                LOG.warn(message);
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
            }

            OcspRespControl repControl = new OcspRespControl();
            repControl.canCacheInfo = true;

            ResponderID responderId = signer.getResponderId(repOpt.isResponderIdByName());
            List<ExtendedExtension> reqExtensions = req.extensions();
            List<Extension> respExtensions = new LinkedList<>();

            ExtendedExtension nonceExtn = removeExtension(reqExtensions, OID.ID_PKIX_OCSP_NONCE);
            if (nonceExtn != null) {
                if (reqOpt.nonceOccurrence() == TripleState.FORBIDDEN) {
                    LOG.warn("nonce forbidden, but is present in the request");
                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
                }

                int len = nonceExtn.extnValueLength();
                int min = reqOpt.nonceMinLen();
                int max = reqOpt.nonceMaxLen();

                if (len < min || len > max) {
                    LOG.warn("length of nonce {} not within [{},{}]", len, min, max);
                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
                }

                repControl.canCacheInfo = false;
                respExtensions.add(nonceExtn);
            } else {
                if (reqOpt.nonceOccurrence() == TripleState.REQUIRED) {
                    LOG.warn("nonce required, but is not present in the request");
                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
                }
            }

            ConcurrentContentSigner concurrentSigner = null;
            if (responder.responderOption().mode() != OcspMode.RFC2560) {
                ExtendedExtension extn = removeExtension(reqExtensions,
                        OID.ID_PKIX_OCSP_PREFSIGALGS);
                if (extn != null) {
                    ASN1InputStream asn1Stream = new ASN1InputStream(extn.getExtnValueStream());

                    List<AlgorithmIdentifier> prefSigAlgs;
                    try {
                        ASN1Sequence seq = ASN1Sequence.getInstance(asn1Stream.readObject());
                        final int size = seq.size();
                        prefSigAlgs = new ArrayList<>(size);
                        for (int i = 0; i < size; i++) {
                            prefSigAlgs.add(AlgorithmIdentifier.getInstance(seq.getObjectAt(i)));
                        }
                    } finally {
                        asn1Stream.close();
                    }
                    concurrentSigner = signer.getSignerForPreferredSigAlgs(prefSigAlgs);
                }
            }

            if (!reqExtensions.isEmpty()) {
                boolean flag = false;
                for (ExtendedExtension m : reqExtensions) {
                    if (m.isCritical()) {
                        flag = true;
                        break;
                    }
                }

                if (flag) {
                    if (LOG.isWarnEnabled()) {
                        List<OID> oids = new LinkedList<>();
                        for (ExtendedExtension m : reqExtensions) {
                            if (m.isCritical()) {
                                oids.add(m.extnType());
                            }
                        }
                        LOG.warn("could not process critial request extensions: {}", oids);
                    }

                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
                }
            }

            if (concurrentSigner == null) {
                concurrentSigner = signer.firstSigner();
            }

            AlgorithmCode cacheDbSigAlgCode = null;
            AlgorithmCode cacheDbCertHashAlgCode = null;
            BigInteger cacheDbSerialNumber = null;
            Integer cacheDbIssuerId = null;

            boolean canCacheDb = (requestsSize == 1) && (responseCacher != null)
                    && (nonceExtn == null) && responseCacher.isOnService();
            if (canCacheDb) {
                // try to find the cached response
                CertID certId = requestList.get(0);
                HashAlgoType reqHashAlgo = certId.issuer().hashAlgorithm();
                if(!reqOpt.allows(reqHashAlgo)) {
                    if (reqHashAlgo != null) {
                        LOG.warn("CertID.hashAlgorithm {} not allowed", reqHashAlgo);
                    } else {
                        LOG.warn("CertID.hashAlgorithm {} not allowed",
                                certId.issuer().hashAlgorithmOID());
                    }
                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
                }

                HashAlgoType certHashAlgo = repOpt.certHashAlgo();
                if (certHashAlgo == null) {
                    certHashAlgo = reqHashAlgo;
                }
                cacheDbCertHashAlgCode = certHashAlgo.algorithmCode();

                cacheDbSigAlgCode = concurrentSigner.algorithmCode();

                cacheDbIssuerId = responseCacher.getIssuerId(certId.issuer());
                cacheDbSerialNumber = certId.serialNumber();

                if (cacheDbIssuerId != null) {
                    OcspRespWithCacheInfo cachedResp = responseCacher.getOcspResponse(
                            cacheDbIssuerId.intValue(), cacheDbSerialNumber, cacheDbSigAlgCode,
                            cacheDbCertHashAlgCode);
                    if (cachedResp != null) {
                        return cachedResp;
                    }
                } else if (master) {
                    // store the issuer certificate in cache database.
                    X509Certificate issuerCert = null;
                    for (OcspStore store : responder.stores()) {
                        issuerCert = store.getIssuerCert(certId.issuer());
                        if (issuerCert != null) {
                            break;
                        }
                    }

                    if (issuerCert != null) {
                        cacheDbIssuerId = responseCacher.storeIssuer(issuerCert);
                    }
                }

                if (cacheDbIssuerId == null) {
                    canCacheDb = false;
                }
            }

            OCSPRespBuilder builder = new OCSPRespBuilder(responderId);

            for (int i = 0; i < requestsSize; i++) {
                OcspRespWithCacheInfo failureOcspResp = processCertReq(requestList.get(i),
                        builder, responder, reqOpt, repOpt, repControl);

                if (failureOcspResp != null) {
                    return failureOcspResp;
                }
            }

            if (repControl.includeExtendedRevokeExtension) {
                respExtensions.add(extension_pkix_ocsp_extendedRevoke);
            }

            if (!respExtensions.isEmpty()) {
                Extensions extns = new Extensions(respExtensions);
                builder.setResponseExtensions(extns);
            }

            TaggedCertSequence certsInResp;
            EmbedCertsMode certsMode = repOpt.embedCertsMode();
            if (certsMode == EmbedCertsMode.SIGNER) {
                certsInResp = signer.sequenceOfCertificate();
            } else if (certsMode == EmbedCertsMode.NONE) {
                certsInResp = null;
            } else {
                // certsMode == EmbedCertsMode.SIGNER_AND_CA
                certsInResp = signer.sequenceOfCertificateChain();
            }

            byte[] encodeOCSPResponse;
            try {
                encodeOCSPResponse = builder.buildOCSPResponse(concurrentSigner,
                        certsInResp, new Date());
            } catch (NoIdleSignerException ex) {
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
            } catch (OCSPException ex) {
                LogUtil.error(LOG, ex, "answer() basicOcspBuilder.build");
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
            }

            // cache response in database
            if (canCacheDb && repControl.canCacheInfo) {
                // Don't cache the response with status UNKNOWN, since this may result in DDoS
                // of storage
                responseCacher.storeOcspResponse(cacheDbIssuerId.intValue(),
                        cacheDbSerialNumber, repControl.cacheThisUpdate,
                        repControl.cacheNextUpdate, cacheDbSigAlgCode,
                        cacheDbCertHashAlgCode, encodeOCSPResponse);
            }

            if (viaGet && repControl.canCacheInfo) {
                ResponseCacheInfo cacheInfo = new ResponseCacheInfo(repControl.cacheThisUpdate);
                if (repControl.cacheNextUpdate != Long.MAX_VALUE) {
                    cacheInfo.setNextUpdate(repControl.cacheNextUpdate);
                }
                return new OcspRespWithCacheInfo(encodeOCSPResponse, cacheInfo);
            } else {
                return new OcspRespWithCacheInfo(encodeOCSPResponse, null);
            }
        } catch (Throwable th) {
            LogUtil.error(LOG, th);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.internalError);
        }
    } // method ask

    private OcspRespWithCacheInfo processCertReq(CertID certId,
            OCSPRespBuilder builder, Responder responder, RequestOption reqOpt,
            ResponseOption repOpt, OcspRespControl repControl) throws IOException {
        HashAlgoType reqHashAlgo = certId.issuer().hashAlgorithm();
        if (!reqOpt.allows(reqHashAlgo)) {
            LOG.warn("CertID.hashAlgorithm {} not allowed", reqHashAlgo);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        CertStatusInfo certStatusInfo = null;
        boolean exceptionOccurs = false;

        BigInteger serial = certId.serialNumber();

        Date now = new Date();
        for (OcspStore store : responder.stores()) {
            try {
                certStatusInfo = store.getCertStatus(now, certId.issuer(), serial,
                        repOpt.isIncludeCerthash(), repOpt.isIncludeInvalidityDate(),
                        responder.responderOption().inheritCaRevocation(),
                        repOpt.certHashAlgo());
                if (certStatusInfo != null) {
                    break;
                }
            } catch (OcspStoreException ex) {
                exceptionOccurs = true;
                LogUtil.error(LOG, ex, "getCertStatus() of CertStatusStore " + store.name());
            }
        }

        if (certStatusInfo == null) {
            if (exceptionOccurs) {
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.tryLater);
            } else {
                certStatusInfo = CertStatusInfo.getIssuerUnknownCertStatusInfo(new Date(), null);
            }
        } // end if

        // certStatusInfo must not be null in any case, since at least one store is configured
        Date thisUpdate = certStatusInfo.thisUpdate();
        if (thisUpdate == null) {
            thisUpdate = new Date();
        }
        Date nextUpdate = certStatusInfo.nextUpdate();

        List<Extension> extensions = new LinkedList<>();
        boolean unknownAsRevoked = false;
        byte[] certStatus;
        switch (certStatusInfo.certStatus()) {
        case GOOD:
            certStatus = bytes_certstatus_good;
            break;
        case ISSUER_UNKNOWN:
            repControl.canCacheInfo = false;
            certStatus = bytes_certstatus_unknown;
            break;
        case UNKNOWN:
        case IGNORE:
            repControl.canCacheInfo = false;
            if (responder.responderOption().mode() == OcspMode.RFC2560) {
                certStatus = bytes_certstatus_unknown;
            } else { // (ocspMode == OCSPMode.RFC6960)
                unknownAsRevoked = true;
                repControl.includeExtendedRevokeExtension = true;
                certStatus = bytes_certstatus_rfc6960_unknown;
            }
            break;
        case REVOKED:
            CertRevocationInfo revInfo = certStatusInfo.revocationInfo();
            certStatus = Template.getEncodeRevokedInfo(
                    repOpt.isIncludeRevReason() ? revInfo.reason() : null,
                    revInfo.revocationTime());

            Date invalidityDate = revInfo.invalidityTime();
            if (repOpt.isIncludeInvalidityDate() && invalidityDate != null
                    && !invalidityDate.equals(revInfo.revocationTime())) {
                extensions.add(Template.getInvalidityDateExtension(invalidityDate));
            }
            break;
        default:
            throw new RuntimeException(
                    "unknown CertificateStatus:" + certStatusInfo.certStatus());
        } // end switch

        byte[] certHash = certStatusInfo.certHash();
        if (certHash != null) {
            extensions.add(Template.getCertHashExtension(certStatusInfo.certHashAlgo(), certHash));
        }

        if (certStatusInfo.archiveCutOff() != null) {
            extensions.add(Template.getArchiveOffExtension(certStatusInfo.archiveCutOff()));
        }

        if (LOG.isDebugEnabled()) {
            String certStatusText = null;
            if (Arrays.equals(certStatus, bytes_certstatus_good)) {
                certStatusText = "good";
            } else if (Arrays.equals(certStatus, bytes_certstatus_unknown)) {
                certStatusText = "unknown";
            } else if (Arrays.equals(certStatus, bytes_certstatus_rfc6960_unknown)) {
                certStatusText = "RFC6969_unknown";
            } else  {
                certStatusText = unknownAsRevoked ? "unknown_as_revoked" : "revoked";
            }

            StringBuilder sb = new StringBuilder(250);
            sb.append("issuer: ").append(certId.issuer()).append(", ");
            sb.append("serialNumber: ")
                .append(LogUtil.formatCsn(certId.serialNumber()))
                .append(", ");
            sb.append("certStatus: ").append(certStatusText).append(", ");
            sb.append("thisUpdate: ").append(thisUpdate).append(", ");
            sb.append("nextUpdate: ").append(nextUpdate);
            if (certHash != null) {
                sb.append(", certHash: ").append(Hex.toHexString(certHash).toUpperCase());
            }
            LOG.debug(sb.toString());
        }

        if (CollectionUtil.isEmpty(extensions)) {
            builder.addResponse(certId, certStatus, thisUpdate, nextUpdate, null);
        } else{
            builder.addResponse(certId, certStatus, thisUpdate, nextUpdate,
                    new Extensions(extensions));
        }

        repControl.cacheThisUpdate = Math.max(repControl.cacheThisUpdate, thisUpdate.getTime());
        if (nextUpdate != null) {
            repControl.cacheNextUpdate = Math.min(repControl.cacheNextUpdate, nextUpdate.getTime());
        }

        return null;
    }

    public HealthCheckResult healthCheck(final Responder responder) {
        HealthCheckResult result = new HealthCheckResult("OCSPResponder");
        boolean healthy = true;

        for (OcspStore store : responder.stores()) {
            boolean storeHealthy = store.isHealthy();
            healthy &= storeHealthy;

            HealthCheckResult storeHealth = new HealthCheckResult(
                    "CertStatusStore." + store.name());
            storeHealth.setHealthy(storeHealthy);
            result.addChildCheck(storeHealth);
        }

        boolean signerHealthy = responder.signer().isHealthy();
        healthy &= signerHealthy;

        HealthCheckResult signerHealth = new HealthCheckResult("Signer");
        signerHealth.setHealthy(signerHealthy);
        result.addChildCheck(signerHealth);

        result.setHealthy(healthy);
        return result;
    } // method healthCheck

    public void setOcspStoreFactoryRegister(
            final OcspStoreFactoryRegister ocspStoreFactoryRegister) {
        this.ocspStoreFactoryRegister = ocspStoreFactoryRegister;
    }

    private ResponderSigner initSigner(final SignerType signerType) throws InvalidConfException {
        X509Certificate[] explicitCertificateChain = null;

        X509Certificate explicitResponderCert = null;
        if (signerType.getCert() != null) {
            explicitResponderCert = parseCert(signerType.getCert());
        }

        if (explicitResponderCert != null) {
            Set<X509Certificate> caCerts = null;
            if (signerType.getCaCerts() != null) {
                caCerts = new HashSet<>();

                for (FileOrValueType certConf : signerType.getCaCerts().getCaCert()) {
                    caCerts.add(parseCert(certConf));
                }
            }

            explicitCertificateChain = X509Util.buildCertPath(explicitResponderCert, caCerts);
        }

        String responderSignerType = signerType.getType();
        String responderKeyConf = signerType.getKey();

        List<String> sigAlgos = signerType.getAlgorithms().getAlgorithm();
        List<ConcurrentContentSigner> singleSigners = new ArrayList<>(sigAlgos.size());
        for (String sigAlgo : sigAlgos) {
            try {
                ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                        responderSignerType,
                        new SignerConf("algo=" + sigAlgo + "," + responderKeyConf),
                        explicitCertificateChain);
                singleSigners.add(requestorSigner);
            } catch (ObjectCreationException ex) {
                throw new InvalidConfException(ex.getMessage(), ex);
            }
        }

        try {
            return new ResponderSigner(singleSigners);
        } catch (CertificateException | IOException ex) {
            throw new InvalidConfException(ex.getMessage(), ex);
        }
    } // method initSigner

    private OcspStore newStore(final StoreType conf,
            final Map<String, DataSourceWrapper> datasources)
            throws InvalidConfException {
        OcspStore store;
        String type = conf.getSource().getType();
        if ("CRL".equalsIgnoreCase(type)) {
            store = new CrlDbCertStatusStore();
        } else if ("XIPKI-DB".equals(type)) {
            store = new DbCertStatusStore();
        } else {
            try {
                store = ocspStoreFactoryRegister.newOcspStore(conf.getSource().getType());
            } catch (ObjectCreationException ex) {
                throw new InvalidConfException("ObjectCreationException of store " + conf.getName()
                        + ":" + ex.getMessage(), ex);
            }
        }
        store.setName(conf.getName());
        Integer interval = conf.getRetentionInterval();
        int retentionInterva = (interval == null) ? -1 : interval.intValue();
        store.setRetentionInterval(retentionInterva);
        store.setUnknownSerialAsGood(getBoolean(conf.isUnknownSerialAsGood(), false));

        store.setIncludeArchiveCutoff(getBoolean(conf.isIncludeArchiveCutoff(), true));
        store.setIncludeCrlId(getBoolean(conf.isIncludeCrlID(), true));

        store.setIgnoreExpiredCert(getBoolean(conf.isIgnoreExpiredCert(), true));
        store.setIgnoreNotYetValidCert(getBoolean(conf.isIgnoreNotYetValidCert(), true));

        String datasourceName = conf.getSource().getDatasource();
        DataSourceWrapper datasource = null;
        if (datasourceName != null) {
            datasource = datasources.get(datasourceName);
            if (datasource == null) {
                throw new InvalidConfException("datasource named '" + datasourceName
                        + "' not defined");
            }
        }
        try {
            store.init(conf.getSource().getConf(), datasource);
        } catch (OcspStoreException ex) {
            throw new InvalidConfException("CertStatusStoreException of store " + conf.getName()
                    + ":" + ex.getMessage(), ex);
        }

        return store;
    } // method initStore

    private Object checkSignature(final byte[] request, final RequestOption requestOption)
            throws OCSPException, CertificateParsingException, InvalidAlgorithmParameterException {
        OCSPRequest req;
        try {
            if (!requestOption.isValidateSignature()) {
                return OcspRequest.getInstance(request);
            }

            if (!OcspRequest.containsSignature(request)) {
                if (requestOption.isSignatureRequired()) {
                    LOG.warn("signature in request required");
                    return unsuccesfulOCSPRespMap.get(OcspResponseStatus.sigRequired);
                } else {
                    return OcspRequest.getInstance(request);
                }
            }

            try {
                req = OCSPRequest.getInstance(request);
            } catch (IllegalArgumentException ex) {
                throw new EncodingException("could not parse OCSP request", ex);
            }
        } catch (EncodingException ex) {
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
        }

        OCSPReq ocspReq = new OCSPReq(req);
        X509CertificateHolder[] certs = ocspReq.getCerts();
        if (certs == null || certs.length < 1) {
            LOG.warn("no certificate found in request to verify the signature");
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
        }

        ContentVerifierProvider cvp;
        try {
            cvp = securityFactory.getContentVerifierProvider(certs[0]);
        } catch (InvalidKeyException ex) {
            String message = ex.getMessage();
            LOG.warn("securityFactory.getContentVerifierProvider, InvalidKeyException: {}",
                    message);
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
        }

        boolean sigValid = ocspReq.isSignatureValid(cvp);
        if (!sigValid) {
            LOG.warn("request signature is invalid");
            return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
        }

        // validate the certPath
        Date referenceTime = new Date();
        if (canBuildCertpath(certs, requestOption, referenceTime)) {
            try {
                return OcspRequest.getInstance(req);
            } catch (EncodingException ex) {
                return unsuccesfulOCSPRespMap.get(OcspResponseStatus.malformedRequest);
            }
        }

        LOG.warn("could not build certpath for the request's signer certificate");
        return unsuccesfulOCSPRespMap.get(OcspResponseStatus.unauthorized);
    } // method checkSignature

    private static boolean canBuildCertpath(final X509CertificateHolder[] certsInReq,
            final RequestOption requestOption, final Date referenceTime) {
        X509Certificate target;
        try {
            target = X509Util.toX509Cert(certsInReq[0].toASN1Structure());
        } catch (CertificateException ex) {
            return false;
        }
        Set<Certificate> certstore = new HashSet<>();

        Set<CertWithEncoded> trustAnchors = requestOption.trustAnchors();
        for (CertWithEncoded m : trustAnchors) {
            certstore.add(m.certificate());
        }

        final int n = certsInReq.length;
        if (n > 1) {
            for (int i = 1; i < n; i++) {
                Certificate cert;
                try {
                    cert = X509Util.toX509Cert(certsInReq[i].toASN1Structure());
                } catch (CertificateException ex) {
                    continue;
                }
                certstore.add(cert);
            }
        }

        Set<X509Certificate> configuredCerts = requestOption.certs();
        if (CollectionUtil.isNonEmpty(configuredCerts)) {
            certstore.addAll(requestOption.certs());
        }

        X509Certificate[] certpath = X509Util.buildCertPath(target, certstore);
        CertpathValidationModel model = requestOption.certpathValidationModel();

        Date now = new Date();
        if (model == null || model == CertpathValidationModel.PKIX) {
            for (X509Certificate m : certpath) {
                if (m.getNotBefore().after(now) || m.getNotAfter().before(now)) {
                    return false;
                }
            }
        } else if (model == CertpathValidationModel.CHAIN) {
            // do nothing
        } else {
            throw new RuntimeException("invalid CertpathValidationModel " + model.name());
        }

        for (int i = certpath.length - 1; i >= 0; i--) {
            X509Certificate targetCert = certpath[i];
            for (CertWithEncoded m : trustAnchors) {
                if (m.equalsCert(targetCert)) {
                    return true;
                }
            }
        }

        return false;
    } // method canBuildCertpath

    private static boolean getBoolean(final Boolean bo, final boolean defaultValue) {
        return (bo == null) ? defaultValue : bo.booleanValue();
    }

    private static InputStream getInputStream(final FileOrValueType conf) throws IOException {
        return (conf.getFile() != null)
                ? new FileInputStream(IoUtil.expandFilepath(conf.getFile()))
                : new ByteArrayInputStream(conf.getValue());
    }

    private static InputStream getInputStream(final FileOrPlainValueType conf) throws IOException {
        return (conf.getFile() != null)
                ? new FileInputStream(IoUtil.expandFilepath(conf.getFile()))
                : new ByteArrayInputStream(conf.getValue().getBytes());
    }

    private static void close(final InputStream stream) {
        if (stream == null) {
            return;
        }

        try {
            stream.close();
        } catch (IOException ex) {
            LOG.warn("could not close stream: {}", ex.getMessage());
        }
    }

    private static X509Certificate parseCert(final FileOrValueType certConf)
            throws InvalidConfException {
        InputStream is = null;
        try {
            is = getInputStream(certConf);
            return X509Util.parseCert(is);
        } catch (IOException | CertificateException ex) {
            String msg = "could not parse certificate";
            if (certConf.getFile() != null) {
                msg += " from file " + certConf.getFile();
            }
            throw new InvalidConfException(msg);
        } finally {
            close(is);
        }
    }

    private static OCSPServer parseConf(final String confFilename) throws InvalidConfException {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            SchemaFactory schemaFact = SchemaFactory.newInstance(
                    javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFact.newSchema(
                    OcspServer.class.getResource("/xsd/ocsp-conf.xsd"));
            unmarshaller.setSchema(schema);
            return (OCSPServer) unmarshaller.unmarshal(
                    new File(IoUtil.expandFilepath(confFilename)));
        } catch (SAXException ex) {
            throw new InvalidConfException("parse profile failed, message: " + ex.getMessage(), ex);
        } catch (JAXBException ex) {
            throw new InvalidConfException(
                    "parse profile failed, message: " + XmlUtil.getMessage(ex), ex);
        }
    }

    private static ExtendedExtension removeExtension(List<ExtendedExtension> extensions,
            OID extnType) {
        ExtendedExtension extn = null;
        for (ExtendedExtension m : extensions) {
            if (extnType == m.extnType()) {
                extn = m;
                break;
            }
        }

        if (extn != null) {
            extensions.remove(extn);
        }

        return extn;
    }

}
