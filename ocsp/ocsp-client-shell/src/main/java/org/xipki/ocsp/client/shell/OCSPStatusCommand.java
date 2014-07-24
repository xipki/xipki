/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ocsp.client.shell;

import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.util.encoders.Hex;
import org.xipki.ocsp.client.api.OCSPRequestor;
import org.xipki.ocsp.client.api.OCSPResponseNotSuccessfullException;
import org.xipki.ocsp.client.api.RequestOptions;
import org.xipki.security.KeyUtil;
import org.xipki.security.SignerUtil;
import org.xipki.security.common.CRLReason;
import org.xipki.security.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "ocsp", name = "status", description="Request certificate status")
public class OCSPStatusCommand extends AbstractOCSPStatusCommand
{
    @Option(name = "-serial",
            description = "Serial number")
    protected String serialNumber;

    @Option(name = "-cert",
            description = "Certificate")
    protected String certFile;

    @Option(name = "-v", aliases="--verbose",
            required = false, description = "Show status verbosely")
    protected Boolean verbose;

    private static final Map<ASN1ObjectIdentifier, String> extensionOidNameMap = new HashMap<>();
    static
    {
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
        extensionOidNameMap.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
        extensionOidNameMap.put(OCSPRequestor.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

    @Override
    protected Object doExecute()
    throws Exception
    {
        if(serialNumber == null && certFile == null)
        {
            System.out.println("Neither serialNumber nor certFile is set");
            return null;
        }

        X509Certificate caCert = IoCertUtil.parseCert(caCertFile);

        byte[] encodedCert = null;
        BigInteger sn;
        if(certFile != null)
        {
            encodedCert = IoCertUtil.read(certFile);
            X509Certificate cert = IoCertUtil.parseCert(certFile);
            sn = cert.getSerialNumber();
        }
        else
        {
            sn = new BigInteger(serialNumber);
        }

        URL serverUrl = getServiceURL();

        RequestOptions options = getRequestOptions();

        BasicOCSPResp basicResp;
        try
        {
            basicResp = requestor.ask(caCert, sn, serverUrl, options);
        }catch(OCSPResponseNotSuccessfullException e)
        {
            System.err.println(e.getMessage());
            return null;
        }

        // check the signature if available
        if(null == basicResp.getSignature())
        {
            System.out.println("Response is not signed");
        }
        else
        {
            X509CertificateHolder[] responderCerts = basicResp.getCerts();
            if(responderCerts == null || responderCerts.length < 1)
            {
                System.err.println("No responder certificate is contained in the response");
            }
            else
            {
                PublicKey responderPubKey = KeyUtil.generatePublicKey(responderCerts[0].getSubjectPublicKeyInfo());
                ContentVerifierProvider cvp = KeyUtil.getContentVerifierProvider(responderPubKey);
                boolean sigValid = basicResp.isSignatureValid(cvp);
                if(sigValid == false)
                {
                    System.err.println("Response is equipped with invalid signature");
                }
                else
                {
                    System.err.println("Response is equipped with valid signature");
                }

                if(verbose != null && verbose.booleanValue())
                {
                    System.out.println("Responder is " + IoCertUtil.canonicalizeName(responderCerts[0].getSubject()));
                }
            }
        }

        boolean extendedRevoke = basicResp.getExtension(OCSPRequestor.id_pkix_ocsp_extendedRevoke) != null;

        SingleResp[] singleResponses = basicResp.getResponses();

        int n = singleResponses == null ? 0 : singleResponses.length;
        if(n == 0)
        {
            System.err.println("Received no status from server");
        }
        else if(n != 1)
        {
            System.err.println("Received status with " + n +
                    " single responses from server, but 1 was requested");
        }
        else
        {
            SingleResp singleResp = singleResponses[0];
            CertificateStatus singleCertStatus = singleResp.getCertStatus();

            String status ;
            if(singleCertStatus == null)
            {
                status = "Good";
            }
            else if(singleCertStatus instanceof RevokedStatus)
            {
                RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
                Date revTime = revStatus.getRevocationTime();

                if(revStatus.hasRevocationReason())
                {
                    int reason = revStatus.getRevocationReason();
                    if(extendedRevoke &&
                            reason == CRLReason.CERTIFICATE_HOLD.getCode() &&
                            revTime.getTime() == 0)
                    {
                        status = "Unknown (RFC6960)";
                    }
                    else
                    {
                        status = "Revoked, reason = "+ CRLReason.forReasonCode(reason).getDescription() +
                                ", revocationTime = " + revTime;
                    }
                }
                else
                {
                    status = "Revoked, no reason, revocationTime = " + revTime;
                }
            }
            else if(singleCertStatus instanceof UnknownStatus)
            {
                status = "Unknown (RFC2560)";
            }
            else
            {
                status = "ERROR";
            }

            StringBuilder msg = new StringBuilder("Certificate status: ");
            msg.append(status);

            Extension extension = singleResp.getExtension(
                    ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
            if(extension != null)
            {
                msg.append("\nCertHash is provided:\n");
                ASN1Encodable extensionValue = extension.getParsedValue();
                CertHash certHash = CertHash.getInstance(extensionValue);
                ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
                byte[] hashValue = certHash.getCertificateHash();

                msg.append("\tHash algo : ").append(hashAlgOid.getId()).append("\n");
                msg.append("\tHash value: ").append(Hex.toHexString(hashValue)).append("\n");
                if(encodedCert != null)
                {
                    MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
                    byte[] expectedHashValue = md.digest(encodedCert);
                    if(Arrays.equals(expectedHashValue, hashValue))
                    {
                        msg.append("\tThis matches the requested certificate");
                    }
                    else
                    {
                        msg.append("\tThis differs from the requested certificate");
                    }
                }
            }

            if(verbose != null && verbose.booleanValue())
            {
                extension = singleResp.getExtension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
                if(extension != null)
                {
                    ASN1Encodable extensionValue = extension.getParsedValue();
                    ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(extensionValue);
                    msg.append("\nArchive-CutOff: ");
                    msg.append(time.getTimeString());
                }

                ASN1ObjectIdentifier sigAlgOid = basicResp.getSignatureAlgOID();
                if(sigAlgOid == null)
                {
                    msg.append(("\nresponse is not signed"));
                }
                else
                {
                    String sigAlgName;
                    if(PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOid))
                    {
                        BasicOCSPResponse asn1BasicOCSPResp =
                                BasicOCSPResponse.getInstance(basicResp.getEncoded());
                        sigAlgName = SignerUtil.getSignatureAlgoName(
                                asn1BasicOCSPResp.getSignatureAlgorithm());
                    }
                    else
                    {
                        sigAlgName = SignerUtil.getSignatureAlgoName(new AlgorithmIdentifier(sigAlgOid));
                    }
                    if(sigAlgName == null)
                    {
                        sigAlgName = "UNKNOWN";
                    }
                    msg.append("\nresponse is signed with ").append(sigAlgName);
                }

                // extensions
                msg.append("\nExtensions: ");

                List<?> extensionOIDs = basicResp.getExtensionOIDs();
                if(extensionOIDs == null || extensionOIDs.size() == 0)
                {
                    msg.append("-");
                }
                else
                {
                    int size = extensionOIDs.size();
                    for(int i = 0; i < size; i++)
                    {
                        ASN1ObjectIdentifier extensionOID = (ASN1ObjectIdentifier) extensionOIDs.get(i);
                        String name = extensionOidNameMap.get(extensionOID);
                        msg.append(name == null ? extensionOID.getId() : name);
                        if(i != size - 1)
                        {
                            msg.append(", ");
                        }
                    }
                }
            }

            System.out.println(msg.toString());
        }
        System.out.println();

        return null;
    }
}
