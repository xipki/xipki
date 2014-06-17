/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.ocsp;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.api.AuditEvent;
import org.xipki.audit.api.AuditEventData;
import org.xipki.audit.api.AuditLevel;
import org.xipki.audit.api.AuditLoggingService;
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.ChildAuditEvent;
import org.xipki.audit.api.PCIAuditEvent;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.OCSPMode;
import org.xipki.ocsp.conf.jaxb.AuditType;
import org.xipki.ocsp.conf.jaxb.CertstatusStoreType;
import org.xipki.ocsp.conf.jaxb.CrlStoreType;
import org.xipki.ocsp.conf.jaxb.CustomStoreType;
import org.xipki.ocsp.conf.jaxb.DbStoreType;
import org.xipki.ocsp.conf.jaxb.MappingType;
import org.xipki.ocsp.conf.jaxb.OCSPResponderType;
import org.xipki.ocsp.conf.jaxb.ObjectFactory;
import org.xipki.ocsp.conf.jaxb.SignerType;
import org.xipki.ocsp.crlstore.CrlCertStatusStore;
import org.xipki.ocsp.dbstore.DbCertStatusStore;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.HashAlgoType;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ObjectIdentifiers;
import org.xml.sax.SAXException;

public class OcspResponder
{
    private static final Logger LOG = LoggerFactory.getLogger(OcspResponder.class);

    private ResponderSigner responderSigner;
    private X509CertificateHolder[] certsInResp;

    private List<CertStatusStore> certStatusStores = new ArrayList<>();

    private DataSourceFactory dataSourceFactory;
    private SecurityFactory securityFactory;
    private PasswordResolver passwordResolver;

    private String confFile;

    private OCSPMode ocspMode;
    private OCSPResponderType conf;
    private RequestOptions requestOptions;
    private boolean auditResponse = false;
    private boolean supportsHttpGet = false;
    private Map<String, String> auditCertprofileMapping = new ConcurrentHashMap<>();

    private AuditLoggingService auditLoggingService;

    public OcspResponder()
    {
    }

    public void init()
    throws OcspResponderException
    {
        boolean successfull = false;
        try
        {
            do_init();
            successfull = true;
        }catch(OcspResponderException e)
        {
            throw e;
        }finally
        {
            if(successfull)
            {
                LOG.info("Started OCSP Responder");
            }
            else
            {
                LOG.error("Could not start OCSP Responder");
            }
            auditLogPCIEvent(successfull, "START");
        }
    }

    private void do_init()
    throws OcspResponderException
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
        if(passwordResolver == null)
        {
            throw new IllegalStateException("passwordResolver is not set");
        }

        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            SchemaFactory schemaFact = SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFact.newSchema(getClass().getResource("/xsd/ocsp-conf.xsd"));
            unmarshaller.setSchema(schema);
            @SuppressWarnings("unchecked")
            JAXBElement<OCSPResponderType> rootElement = (JAXBElement<OCSPResponderType>)
                    unmarshaller.unmarshal(new File(confFile));
            this.conf = rootElement.getValue();
        } catch (JAXBException e)
        {
            throw new OcspResponderException(e);
        } catch (SAXException e)
        {
            throw new OcspResponderException(e);
        }

        // OCSP Mode
        String s = conf.getMode();
        if("RFC6960".equalsIgnoreCase(s))
        {
            ocspMode = OCSPMode.RFC6960;
        }
        else if("RFC2560".equalsIgnoreCase(s))
        {
            ocspMode = OCSPMode.RFC2560;
        }
        else
        {
            throw new OcspResponderException("Invalid OCSP mode '" + s + "'");
        }

        supportsHttpGet = getBoolean(conf.isSupportsHttpGet(), false);

        // RequestOptions
        this.requestOptions = new RequestOptions(conf.getRequest());

        // CertHash hash algorithm of the response
        HashAlgoType certHashAlgo = null;
        s = conf.getCerthashAlgorithm();
        if(s != null)
        {
            String token = s.trim();
            if(token.isEmpty() == false)
            {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if(algo != null && RequestOptions.supportedHashAlgorithms.contains(algo))
                {
                    certHashAlgo = algo;
                }
                else
                {
                    throw new OcspResponderException("Hash algorithm " +token + " is unsupported");
                }
            }
        }

        // Audit
        AuditType auditConf = conf.getAudit();
        if(auditConf == null)
        {
            auditResponse = false;
        }
        else
        {
            auditResponse = auditConf.isEnabled();
            if(auditConf.getCertprofileMappings() != null)
            {
                for(MappingType mapping : auditConf.getCertprofileMappings().getMapping())
                {
                    auditCertprofileMapping.put(mapping.getFrom(), mapping.getTo());
                }
            }
        }

        // Signer
        SignerType signerConf = conf.getSigner();
        X509Certificate[] explicitCertificateChain = null;

        X509Certificate explicitResponderCert = null;
        s = signerConf.getCertFile();
        if(s != null && s.isEmpty() == false)
        {
            explicitResponderCert = parseCert(s);
        }

        if(explicitResponderCert != null)
        {
            Set<X509Certificate> caCerts = new HashSet<>();
            for(String certFile : signerConf.getCaCertFiles().getCaCertFile())
            {
                caCerts.add(parseCert(certFile));
            }

            explicitCertificateChain = IoCertUtil.buildCertPath(explicitResponderCert, caCerts);
        }

        String responderSignerType = signerConf.getType();
        String responderKeyConf = signerConf.getKey();

        List<String> sigAlgos = signerConf.getAlgorithms().getAlgorithm();
        List<ConcurrentContentSigner> signers = new ArrayList<>(sigAlgos.size());
        for(String sigAlgo : sigAlgos)
        {
            try
            {
                ConcurrentContentSigner requestorSigner = securityFactory.createSigner(
                        responderSignerType, "algo?" + sigAlgo + "%" + responderKeyConf,
                        explicitCertificateChain, passwordResolver);
                signers.add(requestorSigner);
            } catch (SignerException e)
            {
                throw new OcspResponderException(e);
            } catch (PasswordResolverException e)
            {
                throw new OcspResponderException(e);
            }
        }

        try
        {
            responderSigner = new ResponderSigner(signers);
        } catch (CertificateEncodingException e)
        {
            throw new OcspResponderException(e);
        } catch (IOException e)
        {
            throw new OcspResponderException(e);
        }

        if(signerConf.isIncludeSignerCertInResp())
        {
            if(signerConf.isIncludeSignerCACertsInResp())
            {
                X509Certificate[] certificateChain = responderSigner.getCertificateChain();
                X509Certificate toplevelCaCert = certificateChain[certificateChain.length - 1];
                if(IoCertUtil.isSelfSigned(toplevelCaCert) == false)
                {
                    throw new OcspResponderException("Could not build certchain of signer up to root CA, but only to "
                            + IoCertUtil.canonicalizeName(toplevelCaCert.getSubjectX500Principal()));
                }

                certsInResp = new X509CertificateHolder[certificateChain.length];
                certsInResp[0] = responderSigner.getCertificateHolder();
                if(certsInResp.length > 1)
                {
                    for(int i = 1; i < certsInResp.length; i++)
                    {
                        X509Certificate certInChain = certificateChain[i];
                        try
                        {
                            certsInResp[i] = new X509CertificateHolder(certInChain.getEncoded());
                        } catch (Exception e)
                        {
                            throw new OcspResponderException("Could not parse certificate "
                                    + IoCertUtil.canonicalizeName(certInChain.getSubjectX500Principal()));
                        }
                    }
                }
            }
            else
            {
                certsInResp = new X509CertificateHolder[]{responderSigner.getCertificateHolder()};
            }
        }

        // CertStatus Stores
        List<CertstatusStoreType> storeConfs = conf.getCertstatusStores().getCertstatusStore();
        for(CertstatusStoreType storeConf : storeConfs)
        {
            CertStatusStore store;
            if(storeConf.getDbStore() != null)
            {
                DbStoreType dbStoreConf = storeConf.getDbStore();
                String databaseConfFile = dbStoreConf.getDbConfFile();

                InputStream confStream = null;
                DataSource dataSource;
                try
                {
                    confStream = new FileInputStream(databaseConfFile);
                    dataSource = dataSourceFactory.createDataSource(confStream, passwordResolver);
                } catch (Exception e)
                {
                    throw new OcspResponderException(e);
                } finally
                {
                    if(confStream != null)
                    {
                        try
                        {
                            confStream.close();
                        }catch(IOException e){}
                    }
                }

                Set<X509Certificate> issuers = null;
                if(dbStoreConf.getCacerts() != null)
                {
                    List<String> caCertFiles = dbStoreConf.getCacerts().getCacert();
                    issuers = new HashSet<>(caCertFiles.size());
                    for(String caCertFile : caCertFiles)
                    {
                        try
                        {
                            issuers.add(IoCertUtil.parseCert(caCertFile));
                        } catch (Exception e)
                        {
                             throw new OcspResponderException(e);
                        }
                    }
                }

                store = new DbCertStatusStore(dataSource, issuers);

                Integer i = storeConf.getRetentionInterval();
                store.setRetentionInterval(i == null ? -1 : i.intValue());
                store.setUnknownSerialAsGood(
                        getBoolean(storeConf.isUnknownSerialAsGood(), false));
            }
            else if(storeConf.getCrlStore() != null)
            {
                CrlStoreType crlStoreConf = storeConf.getCrlStore();
                String caCertFile = crlStoreConf.getCaCertFile();
                String issuerCertFile = crlStoreConf.getIssuerCertFile();
                String crlUrl = crlStoreConf.getCrlUrl();
                String crlFile = crlStoreConf.getCrlFile();

                X509Certificate caCert = parseCert(caCertFile);
                X509Certificate crlIssuerCert = issuerCertFile == null ? null : parseCert(issuerCertFile);

                CrlCertStatusStore crlStore = new CrlCertStatusStore(crlFile, caCert, crlIssuerCert, crlUrl);
                store = crlStore;

                crlStore.setUseUpdateDatesFromCRL(
                        getBoolean(crlStoreConf.isUseUpdateDatesFromCRL(), true));
                boolean caRevoked = getBoolean(crlStoreConf.isCaRevoked(), false);
                crlStore.setCaRevoked(caRevoked);
                if(caRevoked & crlStoreConf.getCaRevocationTime() != null)
                {
                    crlStore.setCaRevocationTime(crlStoreConf.getCaRevocationTime().toGregorianCalendar().getTime());
                }

                Integer i = storeConf.getRetentionInterval();
                store.setRetentionInterval(i == null ? 0 : i.intValue());
                store.setUnknownSerialAsGood(
                        getBoolean(storeConf.isUnknownSerialAsGood(), true));
            }
            else if(storeConf.getCustomStore() != null)
            {
                CustomStoreType customStoreConf = storeConf.getCustomStore();
                String className = customStoreConf.getClassName();
                String conf = customStoreConf.getConf();

                Object instance;
                try
                {
                    Class<?> clazz = Class.forName(className);
                    instance = clazz.newInstance();
                }catch(Exception e)
                {
                    throw new OcspResponderException(e.getMessage(), e);
                }

                if(instance instanceof CertStatusStore)
                {
                    CertStatusStore customStore = (CertStatusStore) instance;
                    store = customStore;

                    try
                    {
                        customStore.init(conf, dataSourceFactory, passwordResolver);
                    } catch (CertStatusStoreException e)
                    {
                        throw new OcspResponderException(e.getMessage(), e);
                    }
                }
                {
                    throw new OcspResponderException(className + " is not instanceof " + CertStatusStore.class.getName());
                }
            }
            else
            {
                throw new RuntimeException("Should not reach here");
            }

            store.setName(storeConf.getName());
            store.setIncludeArchiveCutoff(
                    getBoolean(storeConf.isIncludeArchiveCutoff(), true));
            store.setIncludeCrlID(
                    getBoolean(storeConf.isIncludeCrlID(), true));
            store.setInheritCaRevocation(
                    getBoolean(storeConf.isInheritCaRevocation(), true));
            store.setIncludeCertHash(
                    getBoolean(storeConf.isIncludeCertHash(), false));
            if(certHashAlgo != null)
            {
                store.setCertHashAlgorithm(certHashAlgo);
            }

            this.certStatusStores.add(store);
        }
    }

    public void shutdown()
    {
        LOG.info("Stopped OCSP Responder");
        for(CertStatusStore store : certStatusStores)
        {
            try
            {
                store.shutdown();
            }catch(Exception e)
            {
                LOG.warn("shutdown store {}. {}: {}",
                        new Object[]{store.getName(), e.getClass().getName(), e.getMessage()});
                LOG.debug("shutdown store " + store.getName(), e);
            }
        }

        auditLogPCIEvent(true, "SHUTDOWN");
    }

    public OCSPResp answer(OCSPReq request, AuditEvent auditEvent)
    {
        if(certStatusStores.isEmpty())
        {
            fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, "no certstore is configured");
            return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
        }

        try
        {
            if(request.isSigned())
            {
                if(requestOptions.isValidateSignature())
                {
                    X509CertificateHolder[] certs = request.getCerts();
                    if(certs == null || certs.length < 1)
                    {
                        String message = "no certificate found in request to verify the signature";
                        LOG.warn(message);
                        if(auditEvent != null)
                        {
                            fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
                        }
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
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
                            fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.ERROR, e.getMessage());
                        }
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
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
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.malformedRequest);
                    }
                }
            }
            else
            {
                if(requestOptions.isSignatureRequired())
                {
                    String message = "signature in request required";
                    LOG.warn(message);
                    if(auditEvent != null)
                    {
                        fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.FAILED, message);
                    }
                    return createUnsuccessfullOCSPResp(OcspResponseStatus.sigRequired);
                }
            }

            List<Extension> responseExtensions = new ArrayList<>(2);

            Req[] requestList = request.getRequestList();
            int n = requestList.length;

            RespID respID = new RespID(responderSigner.getResponderId());
            BasicOCSPRespBuilder basicOcspBuilder = new BasicOCSPRespBuilder(respID);
            Extension nonceExtn = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if(nonceExtn != null)
            {
                byte[] nonce = nonceExtn.getExtnValue().getOctets();
                int len = nonce.length;
                int min = requestOptions.getNonceMinLen();
                int max = requestOptions.getNonceMaxLen();

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

                responseExtensions.add(nonceExtn);
            }
            else if(requestOptions.isNonceRequired())
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
            for(int i = 0; i < n; i++)
            {
                ChildAuditEvent childAuditEvent = null;
                if(auditEvent != null)
                {
                    childAuditEvent = new ChildAuditEvent();
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
                else if(requestOptions.allows(reqHashAlgo) == false)
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

                for(CertStatusStore store : certStatusStores)
                {
                    try
                    {
                        certStatusInfo = store.getCertStatus(
                                reqHashAlgo, certID.getIssuerNameHash(), certID.getIssuerKeyHash(),
                                certID.getSerialNumber());
                        if(certStatusInfo.getCertStatus() != CertStatus.ISSUER_UNKNOWN)
                        {
                            break;
                        }
                    } catch (CertStatusStoreException e)
                    {
                        LOG.error("answer() CertStatusStore.getCertStatus. CertStatusStoreException: {}", e.getMessage());
                        LOG.debug("answer() CertStatusStore.getCertStatus", e);
                        if(childAuditEvent != null)
                        {
                            fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.ERROR,
                                    "CertStatusStore.getCertStatus() with CertStatusStoreException");
                        }
                        return createUnsuccessfullOCSPResp(OcspResponseStatus.tryLater);
                    }
                }

                if(childAuditEvent != null)
                {
                    String certProfile = certStatusInfo.getCertProfile();
                    if(certProfile != null)
                    {
                        String auditCertType = auditCertprofileMapping.get(certProfile);
                        if(auditCertType == null)
                        {
                            auditCertType = certProfile;
                        }
                        childAuditEvent.addEventData(new AuditEventData("certType", auditCertType));
                    }
                }

                // certStatusInfo could not be null in any case, since at least one store is configured
                Date thisUpdate = certStatusInfo.getThisUpdate();
                if(thisUpdate == null)
                {
                    thisUpdate = new Date();
                }
                Date nextUpdate = certStatusInfo.getNextUpdate();

                boolean unknownAsRevoked = false;
                CertificateStatus bcCertStatus = null;
                switch(certStatusInfo.getCertStatus())
                {
                    case GOOD:
                        bcCertStatus = null;
                        break;

                    case ISSUER_UNKNOWN:
                        bcCertStatus = new UnknownStatus();
                        break;

                    case UNKNOWN:
                        if(ocspMode == OCSPMode.RFC2560)
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
                        bcCertStatus = new RevokedStatus(revInfo.getRevocationTime(),
                                revInfo.getReason().getCode());
                        break;
                }

                List<Extension> extensions = new LinkedList<>();
                byte[] certHash = certStatusInfo.getCertHash();
                if(certHash != null)
                {
                    ASN1ObjectIdentifier hashAlgoOid =
                            new ASN1ObjectIdentifier(certStatusInfo.getCertHashAlgo().getOid());
                    AlgorithmIdentifier aId = new AlgorithmIdentifier(hashAlgoOid, DERNull.INSTANCE);
                    CertHash bcCertHash = new CertHash(aId, certHash);

                    byte[] encodedCertHash;
                    try
                    {
                        encodedCertHash = bcCertHash.getEncoded();
                    } catch (IOException e)
                    {
                        LOG.error("answer() bcCertHash.getEncoded. IOException: {}", e.getMessage());
                        LOG.debug("answer() bcCertHash.getEncoded", e);
                        if(childAuditEvent != null)
                        {
                            fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.ERROR,
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
                    certStatusText = unknownAsRevoked ? "unknown_as_revoked" : "revoked";
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
                    childAuditEvent.setStatus(AuditStatus.SUCCSEEFULL);
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
                basicOcspBuilder.addResponse(certID, bcCertStatus, thisUpdate, nextUpdate,
                        extensions.isEmpty() ? null : new Extensions(extensions.toArray(new Extension[0])));
            }

            if(includeExtendedRevokeExtension)
            {
                responseExtensions.add(
                        new Extension(ObjectIdentifiers.id_pkix_ocsp_extendedRevoke, true, DERNull.INSTANCE.getEncoded()));
            }

            if(responseExtensions.isEmpty() == false)
            {
                basicOcspBuilder.setResponseExtensions(
                        new Extensions(responseExtensions.toArray(new Extension[0])));
            }

            ConcurrentContentSigner concurrentSigner = null;
            if(ocspMode != OCSPMode.RFC2560)
            {
                Extension ext = request.getExtension(ObjectIdentifiers.id_pkix_ocsp_prefSigAlgs);
                if(ext != null)
                {
                    ASN1Sequence preferredSigAlgs = ASN1Sequence.getInstance(ext.getParsedValue());
                    concurrentSigner = responderSigner.getSigner(preferredSigAlgs);
                }
            }

            if(concurrentSigner == null)
            {
                concurrentSigner = responderSigner.getFirstSigner();
            }

            ContentSigner signer = concurrentSigner.borrowContentSigner();
            BasicOCSPResp basicOcspResp;
            try
            {
                basicOcspResp = basicOcspBuilder.build(signer, certsInResp, new Date());
            } catch (OCSPException e)
            {
                LOG.error("answer() basicOcspBuilder.build. OCSPException: {}", e.getMessage());
                LOG.debug("answer() basicOcspBuilder.build", e);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.ERROR,
                            "BasicOCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
            } finally
            {
                concurrentSigner.returnContentSigner(signer);
            }

            OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
            try
            {
                return ocspRespBuilder.build(OcspResponseStatus.successfull.getStatus(), basicOcspResp);
            } catch (OCSPException e)
            {
                LOG.error("answer() ocspRespBuilder.build. OCSPException: {}", e.getMessage());
                LOG.debug("answer() ocspRespBuilder.build", e);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.ERROR,
                            "OCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
            }

        }catch(Throwable t)
        {
            LOG.error("Throwable. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Throwable", t);

            if(auditEvent != null)
            {
                fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.ERROR,
                        "internal error");
            }

            return createUnsuccessfullOCSPResp(OcspResponseStatus.internalError);
        }
    }

    private static OCSPResp createUnsuccessfullOCSPResp(OcspResponseStatus status)
    {
        return new OCSPResp(new OCSPResponse(
                new org.bouncycastle.asn1.ocsp.OCSPResponseStatus(status.getStatus()), null));
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    public void setDataSourceFactory(DataSourceFactory dataSourceFactory)
    {
        this.dataSourceFactory = dataSourceFactory;
    }

    public void setPasswordResolver(PasswordResolver passwordResolver)
    {
        this.passwordResolver = passwordResolver;
    }

    private static X509Certificate parseCert(String f)
    throws OcspResponderException
    {
        try
        {
            return IoCertUtil.parseCert(f);
        }catch(IOException e)
        {
            throw new OcspResponderException("Could not parse cert " + f, e);
        } catch (CertificateException e)
        {
            throw new OcspResponderException("Could not parse cert " + f, e);
        }
    }

    public void setConfFile(String confFile)
    {
        this.confFile = confFile;
    }

    public HealthCheckResult healthCheck()
    {
        HealthCheckResult result = new HealthCheckResult("OCSPResponder");
        boolean healthy = true;
        for(CertStatusStore store : certStatusStores)
        {
            boolean storeHealthy = store.isHealthy();
            healthy &= storeHealthy;

            HealthCheckResult storeHealth = new HealthCheckResult("CertStatusStore." + store.getName());
            storeHealth.setHealthy(storeHealthy);
            result.addChildCheck(storeHealth);
        }

        boolean signerHealthy = responderSigner.isHealthy();
        healthy &= signerHealthy;

        HealthCheckResult signerHealth = new HealthCheckResult("Signer");
        signerHealth.setHealthy(signerHealthy);
        result.addChildCheck(signerHealth);

        result.setHealthy(healthy);
        return result;
    }

    private static void fillAuditEvent(AuditEvent auditEvent, AuditLevel level, AuditStatus status, String message)
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

    private static void fillAuditEvent(ChildAuditEvent auditEvent, AuditLevel level, AuditStatus status, String message)
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

    public void setAuditLoggingService(AuditLoggingService auditLoggingService)
    {
        this.auditLoggingService = auditLoggingService;
        for(CertStatusStore store : certStatusStores)
        {
            store.setAuditLoggingService(auditLoggingService);
        }
    }

    private void auditLogPCIEvent(boolean successfull, String eventType)
    {
        if(auditLoggingService != null)
        {
            PCIAuditEvent auditEvent = new PCIAuditEvent(new Date());
            auditEvent.setUserId("SYSTEM");
            auditEvent.setEventType(eventType);
            auditEvent.setAffectedResource("CORE");
            if(successfull)
            {
                auditEvent.setStatus(AuditStatus.SUCCSEEFULL.name());
                auditEvent.setLevel(AuditLevel.INFO);
            }
            else
            {
                auditEvent.setStatus(AuditStatus.ERROR.name());
                auditEvent.setLevel(AuditLevel.ERROR);
            }
            auditLoggingService.logEvent(auditEvent);
        }
    }

    public boolean isAuditResponse()
    {
        return auditResponse;
    }

    public boolean supportsHttpGet()
    {
        return supportsHttpGet;
    }

    private static boolean getBoolean(Boolean b, boolean defaultValue)
    {
        return (b == null) ? defaultValue : b.booleanValue();
    }
}
