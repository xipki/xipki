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
import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.F2m;
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
import org.xipki.security.common.ParamChecker;
import org.xipki.security.p10.P12KeypairGenerator;

/**
 * @author Lijun Liao
 */

abstract class CALoadTest extends AbstractLoadTest
{
    static class RSACALoadTest extends CALoadTest
    {
        private BigInteger baseN;

        public RSACALoadTest(RAWorker raWorker, String certProfile,
                String commonNamePrefix, String otherPartOfSubject, int keysize)
        {
            super(raWorker, certProfile, commonNamePrefix, otherPartOfSubject);
            if(keysize % 1024 != 0)
            {
                throw new IllegalArgumentException("invalid RSA keysize " + keysize);
            }

            this.baseN = BigInteger.valueOf(0);
            this.baseN = this.baseN.setBit(keysize - 1);
            for(int i = 32; i < keysize - 1; i += 2)
            {
                this.baseN = this.baseN.setBit(i);
            }
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

    static class ECCALoadTest extends CALoadTest
    {
        private ASN1ObjectIdentifier curveOid;
        private String curveName;
        private ECPoint baseQ;
        private BigInteger baseQx;

        public ECCALoadTest(RAWorker raWorker, String certProfile,
        String commonNamePrefix, String otherPartOfSubject, String curveNameOrOid)
        throws Exception
        {
            super(raWorker, certProfile, commonNamePrefix, otherPartOfSubject);
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
            this.baseQ = ((BCECPublicKey) kp.getPublic()).getQ();

            if(baseQ instanceof ECPoint.F2m)
            {
                ECFieldElement.F2m basePointX = (ECFieldElement.F2m) ((ECPoint.F2m) baseQ).getX();
                baseQx = basePointX.toBigInteger();
            }
            else //if(baseQ instanceof ECPoint.Fp)
            {
                ECFieldElement.Fp basePointX = (ECFieldElement.Fp) ((ECPoint.Fp) baseQ).getX();
                baseQx = basePointX.toBigInteger();
            }

            for(int i = 0; i < 32; i++)
            {
                baseQx = baseQx.clearBit(i);
            }
        }

        @Override
        protected SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index)
        {
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    this.curveOid);

            ECPoint q;
            if(baseQ instanceof ECPoint.F2m)
            {
                ECFieldElement.F2m basePointX = (ECFieldElement.F2m) ((ECPoint.F2m) baseQ).getX();
                BigInteger x = baseQx.add(BigInteger.valueOf(index));

                ECFieldElement.F2m pointX = new F2m(basePointX.getM(),basePointX.getK1(),
                        basePointX.getK2(), basePointX.getK3(), x);
                q = new ECPoint.F2m(baseQ.getCurve(), pointX, baseQ.getY());
            }
            else //if(baseQ instanceof ECPoint.Fp)
            {
                ECFieldElement.Fp basePointX = (ECFieldElement.Fp) ((ECPoint.Fp) baseQ).getX();
                BigInteger x = baseQx.add(BigInteger.valueOf(index));
                ECFieldElement.Fp pointX = new ECFieldElement.Fp(basePointX.getQ(), x);

                q = new ECPoint.Fp(baseQ.getCurve(), pointX, baseQ.getY());
            }

           ASN1OctetString p = (ASN1OctetString)new X9ECPoint(q).toASN1Primitive();
           return new SubjectPublicKeyInfo(algId, p.getOctets());
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(CALoadTest.class);

    private final RAWorker raWorker;
    private final String certProfile;
    private final String commonNamePrefix;
    private final String otherPartOfSubject;

    private AtomicLong index;

    protected abstract SubjectPublicKeyInfo getSubjectPublicKeyInfo(long index);

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public CALoadTest(RAWorker raWorker, String certProfile,
            String commonNamePrefix,
            String otherPartOfSubject)
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotEmpty("certProfile", certProfile);
        ParamChecker.assertNotEmpty("commonNamePrefix", commonNamePrefix);
        ParamChecker.assertNotEmpty("otherPartOfSubject", otherPartOfSubject);

        this.raWorker = raWorker;
        this.certProfile = certProfile;
        this.commonNamePrefix = commonNamePrefix;
        this.otherPartOfSubject = otherPartOfSubject;

        Calendar baseTime = Calendar.getInstance(Locale.UK);
        baseTime.set(Calendar.YEAR, 2014);
        baseTime.set(Calendar.MONTH, 0);
        baseTime.set(Calendar.DAY_OF_MONTH, 1);

        this.index = new AtomicLong(System.nanoTime() / 10000L - baseTime.getTimeInMillis() * 10L);
    }

    private CertRequest nextCertRequest()
    {
        CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

        long thisIndex = index.getAndIncrement();

        X500Name subject = new X500Name("CN=" + commonNamePrefix + thisIndex + "," + otherPartOfSubject);
        certTempBuilder.setSubject(subject);

        SubjectPublicKeyInfo spki = getSubjectPublicKeyInfo(thisIndex);
        if(spki == null)
        {
            return null;
        }

        certTempBuilder.setPublicKey(spki);

        CertTemplate certTemplate = certTempBuilder.build();
        return new CertRequest(1, certTemplate, null);
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                CertRequest certReq = nextCertRequest();
                if(certReq != null)
                {
                    account(1, (testNext(certReq)? 0: 1));
                }
                else
                {
                    account(1, 1);
                }
            }
        }

        private boolean testNext(CertRequest certRequest)
        {
            EnrollCertResult result;
            try
            {
                EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType
                        ("id-1", certProfile, certRequest, new ProofOfPossession());

                EnrollCertRequestType request = new EnrollCertRequestType(Type.CERT_REQ);
                request.addRequestEntry(requestEntry);

                result = raWorker.requestCerts(request, null, null);
            } catch (RAWorkerException e)
            {
                LOG.warn("RAWorkerException: {}", e.getMessage());
                return false;
            } catch (PKIErrorException e)
            {
                LOG.warn("PKIErrorException: {}", e.getMessage());
                return false;
            }

            X509Certificate cert = null;
            if(result != null)
            {
                String id = result.getAllIds().iterator().next();
                CertificateOrError certOrError = result.getCertificateOrError(id);
                cert = (X509Certificate) certOrError.getCertificate();
            }

            if(cert == null)
            {
                return false;
            }

            return true;
        }

    } // End class OcspRequestor

}
