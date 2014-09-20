/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.client.shell.loadtest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.cmp.client.type.EnrollCertRequestEntryType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType;
import org.xipki.ca.cmp.client.type.EnrollCertRequestType.Type;
import org.xipki.ca.common.CertificateOrError;
import org.xipki.ca.common.EnrollCertResult;
import org.xipki.ca.common.PKIErrorException;
import org.xipki.ca.common.RAWorkerException;
import org.xipki.security.SignerUtil;
import org.xipki.security.common.AbstractLoadTest;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ObjectIdentifiers;
import org.xipki.security.common.ParamChecker;
import org.xipki.security.p10.P12KeypairGenerator;

/**
 * @author Lijun Liao
 */

abstract class CALoadTestEnroll extends AbstractLoadTest
{
    private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();
    static class RSACALoadTest extends CALoadTestEnroll
    {
        private final BigInteger baseN;

        public RSACALoadTest(RAWorker raWorker, String certProfile,
                String subjectTemplate, int keysize, RandomDN randomDN, int n)
        {
            super(raWorker, certProfile, subjectTemplate, randomDN, n);
            if(keysize % 1024 != 0)
            {
                throw new IllegalArgumentException("invalid RSA keysize " + keysize);
            }

            BigInteger _baseN = BigInteger.valueOf(0);
            _baseN = _baseN.setBit(keysize - 1);
            for(int i = 32; i < keysize - 1; i += 2)
            {
                _baseN = _baseN.setBit(i);
            }
            this.baseN = _baseN;
        }

        @Override
        protected SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index)
        {
            BigInteger modulus = baseN.add(BigInteger.valueOf(index));

            try
            {
                return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                        SignerUtil.generateRSAPublicKeyParameter(
                                org.xipki.security.KeyUtil.generateRSAPublicKey(modulus,
                                        BigInteger.valueOf(65537))));
            } catch (InvalidKeySpecException e)
            {
                LOG.warn("InvalidKeySpecException: {}", e.getMessage());
                return null;
            } catch (IOException e)
            {
                LOG.warn("IOException: {}", e.getMessage());
                return null;
            }
        }
    }

    static class ECCALoadTest extends CALoadTestEnroll
    {
        private final ASN1ObjectIdentifier curveOid;
        private final String curveName;
        private final BigInteger basePublicKey;

        public ECCALoadTest(RAWorker raWorker, String certProfile, String subjectTemplate,
        String curveNameOrOid, RandomDN randomDN, int n)
        throws Exception
        {
            super(raWorker, certProfile, subjectTemplate, randomDN, n);

            boolean isOid;
            try
            {
                new ASN1ObjectIdentifier(curveNameOrOid);
                isOid = true;
            }catch(Exception e)
            {
                isOid = false;
            }

            if(isOid)
            {
                this.curveOid = new ASN1ObjectIdentifier(curveNameOrOid);
                this.curveName = P12KeypairGenerator.ECDSAIdentityGenerator.getCurveName(this.curveOid);
            }
            else
            {
                this.curveName = curveNameOrOid;
                this.curveOid = P12KeypairGenerator.ECDSAIdentityGenerator.getCurveOID(this.curveName);
                if(this.curveOid == null)
                {
                    throw new IllegalArgumentException("No OID is defined for the curve " + this.curveName);
                }
            }

            KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
            kpgen.initialize(spec);
            KeyPair kp = kpgen.generateKeyPair();

            ECPoint baseQ = ((BCECPublicKey) kp.getPublic()).getQ();
            basePublicKey = new BigInteger(baseQ.getEncoded(false));
        }

        @Override
        protected SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index)
        {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    this.curveOid);

            BigInteger publicKey = basePublicKey.add(BigInteger.valueOf(index));
            return new SubjectPublicKeyInfo(algId, publicKey.toByteArray());
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(CALoadTestEnroll.class);

    private final RAWorker raWorker;
    private final String certProfile;
    private final X500Name subjectTemplate;
    private final ASN1ObjectIdentifier subjectRDNForIncrement;

    private AtomicLong index;
    private final int n;

    protected abstract SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index);

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public CALoadTestEnroll(RAWorker raWorker, String certProfile, String subjectTemplate, RandomDN randomDN, int n)
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotEmpty("certProfile", certProfile);
        ParamChecker.assertNotEmpty("subjectTemplate", subjectTemplate);
        if(n < 1)
        {
            throw new IllegalArgumentException("non-positive n " + n + " is not allowed");
        }
        this.n = n;

        this.subjectTemplate = IoCertUtil.sortX509Name(new X500Name(subjectTemplate));

        ASN1ObjectIdentifier[] rdnOidsForIncrement = new ASN1ObjectIdentifier[]
        {
                    ObjectIdentifiers.DN_O, ObjectIdentifiers.DN_OU, ObjectIdentifiers.DN_GIVENNAME,
                    ObjectIdentifiers.DN_SURNAME, ObjectIdentifiers.DN_STREET, ObjectIdentifiers.DN_POSTAL_CODE,
                    ObjectIdentifiers.DN_CN};

        if(randomDN != null)
        {
            switch(randomDN)
            {
                case CN:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_CN;
                    break;
                case O:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_O;
                    break;
                case OU:
                    this.subjectRDNForIncrement = ObjectIdentifiers.DN_OU;
                    break;
                default:
                    throw new RuntimeException("should not reach here");
            }

            if(this.subjectTemplate.getRDNs(this.subjectRDNForIncrement).length == 0)
            {
                throw new IllegalArgumentException("subjectTemplate does not contain DN field " +
                        ObjectIdentifiers.oidToDisplayName(this.subjectRDNForIncrement));
            }
        }
        else
        {
            ASN1ObjectIdentifier _subjectRDNForIncrement = null;
            List<ASN1ObjectIdentifier> attrTypes = Arrays.asList(this.subjectTemplate.getAttributeTypes());
            for(ASN1ObjectIdentifier oid : rdnOidsForIncrement)
            {
                if(attrTypes.contains(oid))
                {
                    _subjectRDNForIncrement = oid;
                    break;
                }
            }

            if(_subjectRDNForIncrement == null)
            {
                throw new IllegalArgumentException("invalid subjectTemplate");
            }
            this.subjectRDNForIncrement = _subjectRDNForIncrement;
        }

        this.raWorker = raWorker;
        this.certProfile = certProfile;

        Calendar baseTime = Calendar.getInstance(Locale.UK);
        baseTime.set(Calendar.YEAR, 2014);
        baseTime.set(Calendar.MONTH, 0);
        baseTime.set(Calendar.DAY_OF_MONTH, 1);

        this.index = new AtomicLong(System.nanoTime() / 10000L - baseTime.getTimeInMillis() * 10L);
    }

    private Map<Integer, CertRequest> nextCertRequests()
    {
        Map<Integer, CertRequest> certRequests = new HashMap<>();
        for(int i = 0; i < n; i++)
        {
            final int certId = i + 1;
            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

            long thisIndex = index.getAndIncrement();

            this.subjectTemplate.getRDNs();
            certTempBuilder.setSubject(incrementX500Name(thisIndex));

            SubjectPublicKeyInfo spki = getSubjectPublicKeyInfo(thisIndex);
            if(spki == null)
            {
                return null;
            }

            certTempBuilder.setPublicKey(spki);

            CertTemplate certTemplate = certTempBuilder.build();
            CertRequest certRequest = new CertRequest(certId, certTemplate, null);
            certRequests.put(certId, certRequest);
        }
        return certRequests;
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                Map<Integer, CertRequest> certReqs = nextCertRequests();
                if(certReqs != null)
                {
                    int size = certReqs.size();
                    int nSucc = testNext(certReqs);
                    int failed = size - nSucc;
                    if(failed < 0)
                    {
                        failed = size;
                    }
                    account(size, failed);
                }
                else
                {
                    account(1, 1);
                }
            }
        }

        private int testNext(Map<Integer, CertRequest> certRequests)
        {
            EnrollCertResult result;
            try
            {
                EnrollCertRequestType request = new EnrollCertRequestType(Type.CERT_REQ);
                for(Integer certId : certRequests.keySet())
                {
                    String id = "id-" + certId;
                    EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType
                            (id, certProfile, certRequests.get(certId), RA_VERIFIED);

                    request.addRequestEntry(requestEntry);
                }

                result = raWorker.requestCerts(request, null, null);
            } catch (RAWorkerException | PKIErrorException e)
            {
                LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
                return 0;
            }

            if(result == null)
            {
                return 0;
            }

            Set<String> ids = result.getAllIds();
            int nSuccess = 0;
            for(String id : ids)
            {
                CertificateOrError certOrError = result.getCertificateOrError(id);
                X509Certificate cert = (X509Certificate) certOrError.getCertificate();

                if(cert != null)
                {
                    nSuccess++;
                }
            }

            return nSuccess;
        }

    }

    private X500Name incrementX500Name(long index)
    {
        RDN[] baseRDNs = subjectTemplate.getRDNs();

        final int n = baseRDNs.length;
        RDN[] newRDNS = new RDN[n];

        boolean incremented = false;
        for(int i = 0; i < n; i++)
        {
            RDN rdn = baseRDNs[i];
            if(incremented == false)
            {
                if(rdn.getFirst().getType().equals(subjectRDNForIncrement))
                {
                    String text = IETFUtils.valueToString(rdn.getFirst().getValue());
                    rdn = new RDN(subjectRDNForIncrement, new DERUTF8String(text + index));
                    incremented = true;
                }
            }

            newRDNS[i] = rdn;
        }
        return new X500Name(newRDNS);
    }
}
