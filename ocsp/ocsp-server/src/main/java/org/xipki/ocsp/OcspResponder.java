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

package org.xipki.ocsp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
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
import org.xipki.audit.api.AuditStatus;
import org.xipki.audit.api.ChildAuditEvent;
import org.xipki.database.api.DataSource;
import org.xipki.database.api.DataSourceFactory;
import org.xipki.ocsp.api.CertRevocationInfo;
import org.xipki.ocsp.api.CertStatus;
import org.xipki.ocsp.api.CertStatusInfo;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertStatusStoreException;
import org.xipki.ocsp.api.HashAlgoType;
import org.xipki.ocsp.crlstore.CrlCertStatusStore;
import org.xipki.ocsp.dbstore.DbCertStatusStore;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.PasswordResolver;
import org.xipki.security.api.PasswordResolverException;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;
import org.xipki.security.common.HealthCheckResult;
import org.xipki.security.common.IoCertUtil;

public class OcspResponder
{
    public static final String signer_type = "signer.type";
    public static final String signer_conf = "signer.conf";
    public static final String signer_cert = "signer.cert";
    public static final String dbstore_prefix = "dbstore.";
    public static final String crlstore_prefix = "crlstore.";
    public static final String enabled_suffix = ".enabled";
    public static final String conffile_suffix = ".confFile";
    public static final String useUpdateDatesFromCRL_suffix = ".useUpdateDatesFromCRL";
    public static final String crlFile_SUFFIX = ".crlFile";
    public static final String cacertFile_SUFFIX = ".cacertFile";
    public static final String issuerCertFile_SUFFIX = ".issuerCertFile";
    public static final String unknownSerialAsGood_SUFFIX = ".unknownSerialAsGood";
    public static final String req_nonce_required = "req.nonce.required";
    public static final String req_nonce_len_min = "req.nonce.minlen";
    public static final String req_nonce_len_max = "req.nonce.maxlen";
    public static final String req_hash_algos = "req.hashalgos";
    public static final String resp_certhash_algo = "resp.certhash.algo";

    private static final Set<HashAlgoType> supportedHashAlgorithms = new HashSet<HashAlgoType>();

    private static final Logger LOG = LoggerFactory.getLogger(OcspResponder.class);
    private boolean includeCertHash = false;
    private boolean requireReqSigned = false;
    private boolean checkReqSignature = false;

    private boolean reqNonceRequired = false;
    private int reqNonceMinLen = 8;
    private int reqNonceMaxLen = 32;
    private Set<HashAlgoType> reqHashAlgos;
    private HashAlgoType respHashAlgo;

    private ResponderSigner responder;

    private List<CertStatusStore> certStatusStores = new ArrayList<CertStatusStore>();

    private DataSourceFactory dataSourceFactory;
    private SecurityFactory securityFactory;
    private PasswordResolver passwordResolver;

    private String confFile;

    static
    {
        supportedHashAlgorithms.add(HashAlgoType.SHA1);
        supportedHashAlgorithms.add(HashAlgoType.SHA224);
        supportedHashAlgorithms.add(HashAlgoType.SHA256);
        supportedHashAlgorithms.add(HashAlgoType.SHA384);
        supportedHashAlgorithms.add(HashAlgoType.SHA512);
    }

    public OcspResponder()
    {
    }

    public void init()
        throws OCSPResponderException
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

        Properties props = new Properties();
        FileInputStream configStream = null;
        try
        {
            configStream = new FileInputStream(confFile);
            props.load(configStream);
        } catch (FileNotFoundException e)
        {
            throw new OCSPResponderException(e);
        } catch (IOException e)
        {
            throw new OCSPResponderException(e);
        }finally
        {
            if(configStream != null)
            {
                try
                {
                    configStream.close();
                }catch(IOException e)
                {}
            }
        }

        String s;

        s = props.getProperty(req_nonce_required, "false");
        reqNonceRequired = Boolean.parseBoolean(s);

        s = props.getProperty(req_nonce_len_min, "8");
        reqNonceMinLen = Integer.parseInt(s);

        s = props.getProperty(req_nonce_len_max, "32");
        reqNonceMaxLen = Integer.parseInt(s);

        s = props.getProperty(req_hash_algos);
        reqHashAlgos = new HashSet<HashAlgoType>();
        if(s != null)
        {
            StringTokenizer st = new StringTokenizer(s, ", ");
            while(st.hasMoreTokens())
            {
                String token = st.nextToken().trim();
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if(algo != null && supportedHashAlgorithms.contains(algo))
                {
                    reqHashAlgos.add(algo);
                }
                else
                {
                    throw new OCSPResponderException("Hash algorithm " + token + " is unsupported");
                }
            }
        }
        else
        {
            reqHashAlgos.addAll(supportedHashAlgorithms);
        }

        s = props.getProperty(resp_certhash_algo);
        if(s != null)
        {
            String token = s.trim();
            if(token.isEmpty() == false)
            {
                HashAlgoType algo = HashAlgoType.getHashAlgoType(token);
                if(algo != null && supportedHashAlgorithms.contains(algo))
                {
                    respHashAlgo = algo;
                }
                else
                {
                    throw new OCSPResponderException("Hash algorithm " +token + " is unsupported");
                }
            }
        }

        X509Certificate requestorCert = null;
        s = props.getProperty(signer_cert);
        if(s != null && s.isEmpty() == false)
        {
            requestorCert = parseCert(s);
        }

        String requestorSignerType = props.getProperty(signer_type);
        String requestorSignerConf = props.getProperty(signer_conf);

        ConcurrentContentSigner requestorSigner;
        try
        {
            requestorSigner = securityFactory.createSigner(
                    requestorSignerType, requestorSignerConf, requestorCert, passwordResolver);
        } catch (SignerException e)
        {
            throw new OCSPResponderException(e);
        } catch (PasswordResolverException e)
        {
            throw new OCSPResponderException(e);
        }

        try
        {
            responder = new ResponderSigner(requestorSigner);
        } catch (CertificateEncodingException e)
        {
            throw new OCSPResponderException(e);
        } catch (IOException e)
        {
            throw new OCSPResponderException(e);
        }

        List<String> dbStoreNames = new ArrayList<String>();

        for(Object _propKey : props.keySet())
        {
            String propKey = (String) _propKey;
            if(propKey.startsWith(dbstore_prefix) && propKey.endsWith(conffile_suffix))
            {
                String certstoreName = propKey.substring(dbstore_prefix.length(),
                        propKey.length() - conffile_suffix.length());

                String enabled = props.getProperty(dbstore_prefix + certstoreName + enabled_suffix, "true");
                if(Boolean.parseBoolean(enabled) && dbStoreNames.contains(certstoreName) == false)
                {
                    dbStoreNames.add(certstoreName);
                }
                else
                {
                    LOG.info("Database-based certificate store " + certstoreName + " is disabled");
                }
            }
        }

        List<String> crlStoreNames = new ArrayList<String>();

        for(Object _propKey : props.keySet())
        {
            String propKey = (String) _propKey;
            if(propKey.startsWith(crlstore_prefix) && propKey.endsWith(crlFile_SUFFIX))
            {
                String certstoreName = propKey.substring(crlstore_prefix.length(),
                        propKey.length() - crlFile_SUFFIX.length());

                String enabled = props.getProperty(crlstore_prefix + certstoreName + enabled_suffix, "true");
                if(Boolean.parseBoolean(enabled) && crlStoreNames.contains(certstoreName) == false)
                {
                    crlStoreNames.add(certstoreName);
                }
                else
                {
                    LOG.info("CRL-based certificate store " + certstoreName + " is disabled");
                }
            }
        }

        if(dbStoreNames.isEmpty() && crlStoreNames.isEmpty())
        {
            throw new OCSPResponderException("No Certificate Store is configured");
        }

        if(dbStoreNames.isEmpty() == false)
        {
            for(String storeName : dbStoreNames)
            {
                FileInputStream confStream = null;

                String tmp = props.getProperty(dbstore_prefix + storeName + unknownSerialAsGood_SUFFIX);
                boolean unknownSerialAsGood = (tmp == null) ? false : Boolean.parseBoolean(tmp);

                String dbConfFile = props.getProperty(dbstore_prefix + storeName + conffile_suffix);
                DataSource dataSource;
                try
                {
                    confStream = new FileInputStream(dbConfFile);
                    dataSource = dataSourceFactory.createDataSource(confStream, passwordResolver);
                } catch (IOException e)
                {
                        throw new OCSPResponderException(e);
                } catch (SQLException e)
                {
                        throw new OCSPResponderException(e);
                } catch (PasswordResolverException e)
                {
                        throw new OCSPResponderException(e);
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

                DbCertStatusStore certStatusStore = new DbCertStatusStore(storeName, dataSource, unknownSerialAsGood);
                this.certStatusStores.add(certStatusStore);
            }
        }

        if(crlStoreNames.isEmpty() == false)
        {
            for(String storeName : crlStoreNames)
            {
                String tmp = props.getProperty(crlstore_prefix + storeName + unknownSerialAsGood_SUFFIX);
                boolean unknownSerialAsGood = (tmp == null) ? false : Boolean.parseBoolean(tmp);

                String key = crlstore_prefix + storeName + crlFile_SUFFIX;
                String crlFile = props.getProperty(key);
                if(crlFile == null)
                {
                    throw new OCSPResponderException(key + " is not set");
                }

                key = crlstore_prefix + storeName + cacertFile_SUFFIX;
                String cacertFile = props.getProperty(key);
                if(cacertFile == null)
                {
                    throw new OCSPResponderException(key + " is not set");
                }

                String issuercertFile = props.getProperty(crlstore_prefix + storeName + issuerCertFile_SUFFIX);
                String s1 = props.getProperty(crlstore_prefix + storeName + useUpdateDatesFromCRL_suffix);
                boolean useUpdateDatesFromCRL = (s1 == null)? true : Boolean.getBoolean(s1);

                X509Certificate caCert = parseCert(cacertFile);
                X509Certificate crlIssuerCert = issuercertFile == null ? null : parseCert(issuercertFile);

                CrlCertStatusStore certStatusStore = new CrlCertStatusStore(storeName, crlFile, caCert, crlIssuerCert,
                            useUpdateDatesFromCRL, unknownSerialAsGood);
                this.certStatusStores.add(certStatusStore);
            }
        }

    }

    public OCSPResp answer(OCSPReq request, AuditEvent auditEvent)
    {
        try
        {
            if(request.isSigned())
            {
                if(checkReqSignature)
                {
                    X509CertificateHolder[] certs = request.getCerts();
                    if(certs == null || certs.length < 1)
                    {
                        String message = "no certificate found in request to verify the signature";
                        LOG.warn(message);
                        if(auditEvent != null)
                        {
                            fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.failed, message);
                        }
                        return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
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
                            fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.error, e.getMessage());
                        }
                        return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
                    }

                    boolean sigValid = request.isSignatureValid(cvp);
                    if(!sigValid)
                    {
                        String message = "request signature is invalid";
                        LOG.warn(message);
                        if(auditEvent != null)
                        {
                            fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.failed, message);
                        }
                        return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
                    }
                }
            }
            else
            {
                if(requireReqSigned)
                {
                    String message = "signature in request required";
                    LOG.warn(message);
                    if(auditEvent != null)
                    {
                        fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.failed, message);
                    }
                    return createUnsuccessfullOCSPResp(CSPResponseStatus.sigRequired);
                }
            }

            Req[] requestList = request.getRequestList();
            int n = requestList.length;

            RespID respID = new RespID(responder.getResponderId());
            BasicOCSPRespBuilder basicOcspBuilder = new BasicOCSPRespBuilder(respID);
            Extension nonceExtn = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if(nonceExtn != null)
            {
                byte[] nonce = nonceExtn.getExtnValue().getOctets();
                int len = nonce.length;
                if(len < reqNonceMinLen || len > reqNonceMaxLen)
                {
                    LOG.warn("length of nonce {} not within [{},{}]", new Object[]{len, reqNonceMinLen, reqNonceMaxLen});
                    if(auditEvent != null)
                    {
                        StringBuilder sb = new StringBuilder();
                        sb.append("length of nonce ").append(len);
                        sb.append(" not within [").append(reqNonceMinLen).append(", ").append(reqNonceMaxLen);
                        fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.failed, sb.toString());
                    }
                    return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
                }

                basicOcspBuilder.setResponseExtensions(new Extensions(nonceExtn));
            }
            else if(reqNonceRequired)
            {
                String message = "nonce required, but is not present in the request";
                LOG.warn(message);
                if(auditEvent != null)
                {
                    fillAuditEvent(auditEvent, AuditLevel.INFO, AuditStatus.failed, message);
                }
                return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
            }

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
                        fillAuditEvent(childAuditEvent, AuditLevel.INFO, AuditStatus.failed,
                                "unknown CertID.hashAlgorithm " + certIdHashAlgo);
                    }
                    return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
                }
                else if(reqHashAlgos.contains(reqHashAlgo) == false)
                {
                    LOG.warn("CertID.hashAlgorithm {} not allowed", certIdHashAlgo);
                    if(childAuditEvent != null)
                    {
                        fillAuditEvent(childAuditEvent, AuditLevel.INFO, AuditStatus.failed,
                                "CertID.hashAlgorithm " + certIdHashAlgo + " not allowed");
                    }
                    return createUnsuccessfullOCSPResp(CSPResponseStatus.malformedRequest);
                }

                CertStatusInfo certStatusInfo = null;

                for(CertStatusStore store : certStatusStores)
                {
                    HashAlgoType certHashAlgo = null;
                    if(includeCertHash)
                    {
                        certHashAlgo = (respHashAlgo != null) ? respHashAlgo : reqHashAlgo;
                    }

                    try
                    {
                        certStatusInfo = store.getCertStatus(
                                reqHashAlgo, certID.getIssuerNameHash(), certID.getIssuerKeyHash(),
                                certID.getSerialNumber(), includeCertHash, certHashAlgo);
                        if(certStatusInfo.getCertStatus() != CertStatus.ISSUER_UNKNOWN)
                        {
                            break;
                        }
                    } catch (CertStatusStoreException e)
                    {
                        LOG.error("answer() CertStatusStore.getCertStatus. CertStatusStoreException: {}", e.getMessage());
                        LOG.error("answer() CertStatusStore.getCertStatus", e);
                        if(childAuditEvent != null)
                        {
                            fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.error,
                                    "CertStatusStore.getCertStatus() with CertStatusStoreException");
                        }
                        return createUnsuccessfullOCSPResp(CSPResponseStatus.tryLater);
                    }
                }

                // certStatusInfo could not be null in any case, since at least one store is configured
                Date thisUpdate = certStatusInfo.getThisUpdate();
                if(thisUpdate == null)
                {
                    thisUpdate = new Date();
                }
                Date nextUpdate = certStatusInfo.getNextUpdate();

                CertificateStatus bcCertStatus = null;
                switch(certStatusInfo.getCertStatus())
                {
                    case GOOD:
                        break;
                    case ISSUER_UNKNOWN:
                    case UNKNOWN:
                        bcCertStatus = new UnknownStatus();
                        break;
                    case REVOCATED:
                        CertRevocationInfo revInfo = certStatusInfo.getRevocationInfo();
                        bcCertStatus = new RevokedStatus(revInfo.getRevocationTime(), revInfo.getReason());
                        break;
                }

                Extension certHashExtension = null;

                Extensions extensions = null;
                byte[] certHash = certStatusInfo.getCertHash();
                if(includeCertHash && certHash != null)
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
                        LOG.error("answer() bcCertHash.getEncoded", e);
                        if(childAuditEvent != null)
                        {
                            fillAuditEvent(childAuditEvent, AuditLevel.ERROR, AuditStatus.error,
                                    "CertHash.getEncoded() with IOException");
                        }
                        return createUnsuccessfullOCSPResp(CSPResponseStatus.internalError);
                    }

                    certHashExtension = new Extension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash,
                            false, encodedCertHash);

                    extensions = new Extensions(certHashExtension);
                }

                String certStatusText;
                if(bcCertStatus instanceof UnknownStatus)
                {
                    certStatusText = "unknown";
                }
                else if(bcCertStatus instanceof RevokedStatus)
                {
                    certStatusText = "revoked";
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
                    childAuditEvent.setStatus(AuditStatus.successfull);
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

                    sb.append("issuerKeyHash: ") .append(Hex.toHexString(certID.getIssuerKeyHash()) .toUpperCase()).append(", ");
                    sb.append("issuerNameHash: ").append(Hex.toHexString(certID.getIssuerNameHash()).toUpperCase()).append(", ");
                    sb.append("serialNumber: ").append(certID.getSerialNumber()).append(", ");
                    sb.append("certStatus: ").append(certStatusText).append(", ");
                    sb.append("thisUpdate: ").append(thisUpdate).append(", ");
                    sb.append("nextUpdate: ").append(nextUpdate).append(", ");
                    sb.append("certHash: ").append(hexCertHash);
                    LOG.debug(sb.toString());
                }
                basicOcspBuilder.addResponse(certID, bcCertStatus, thisUpdate, nextUpdate, extensions);
            }

            ConcurrentContentSigner concurrentSigner = responder.getSigner();
            ContentSigner signer = concurrentSigner.borrowContentSigner();
            BasicOCSPResp basicOcspResp;
            try
            {
                basicOcspResp = basicOcspBuilder.build(signer,
                        new X509CertificateHolder[]{responder.getCertificate()}, new Date());
            } catch (OCSPException e)
            {
                LOG.error("answer() basicOcspBuilder.build. OCSPException: {}", e.getMessage());
                LOG.debug("answer() basicOcspBuilder.build", e);
                if(auditEvent != null)
                {
                    auditEvent.cleanChildAuditEvents(true, true, "message");
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.error,
                            "BasicOCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(CSPResponseStatus.internalError);
            } finally
            {
                concurrentSigner.returnContentSigner(signer);
            }

            OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
            try
            {
                return ocspRespBuilder.build(CSPResponseStatus.successfull.getStatus(), basicOcspResp);
            } catch (OCSPException e)
            {
                LOG.error("answer() ocspRespBuilder.build. OCSPException: {}", e.getMessage());
                LOG.debug("answer() ocspRespBuilder.build", e);
                if(auditEvent != null)
                {
                    auditEvent.cleanChildAuditEvents(true, true, "message");
                    fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.error,
                            "OCSPRespBuilder.build() with OCSPException");
                }
                return createUnsuccessfullOCSPResp(CSPResponseStatus.internalError);
            }

        }catch(Throwable t)
        {
            LOG.error("Throwable. {}: {}", t.getClass().getName(), t.getMessage());
            LOG.debug("Throwable", t);

            if(auditEvent != null)
            {
                auditEvent.cleanChildAuditEvents(true, true, "message");
                fillAuditEvent(auditEvent, AuditLevel.ERROR, AuditStatus.error,
                        "internal error");
            }

            return createUnsuccessfullOCSPResp(CSPResponseStatus.internalError);
        }
    }

    private static OCSPResp createUnsuccessfullOCSPResp(CSPResponseStatus status)
    {
        return new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status.getStatus()), null));
    }

    public void setIncludeCertHash(boolean includeCertHash)
    {
        this.includeCertHash = includeCertHash;
    }

    public void setRequireReqSigned(boolean requireReqSigned)
    {
        this.requireReqSigned = requireReqSigned;
    }

    public void setCheckReqSignature(boolean checkReqSignature)
    {
        this.checkReqSignature = checkReqSignature;
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

    private static X509Certificate parseCert(String f) throws OCSPResponderException
    {
        try
        {
            return IoCertUtil.parseCert(f);
        }catch(IOException e)
        {
            throw new OCSPResponderException(e);
        } catch (CertificateException e)
        {
            throw new OCSPResponderException(e);
        }
    }

    public void setConfFile(String confFile)
    {
        this.confFile = confFile;
    }

    public HealthCheckResult healthCheck()
    {
        HealthCheckResult result = new HealthCheckResult();
        boolean healthy = true;
        for(CertStatusStore store : certStatusStores)
        {
            boolean storeHealthy = store.isHealthy();
            healthy &= storeHealthy;
            result.putStatus("CertStatusStore." + store.getName() + ".healthy", storeHealthy);
        }

        boolean signerHealthy = responder.getSigner().isHealthy();
        healthy &= signerHealthy;
        result.putStatus("Signer.healthy", signerHealthy);

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
}
