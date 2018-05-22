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

package org.xipki.ocsp.client.shell;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.common.util.Hex;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.CmdFailure;
import org.xipki.security.CrlReason;
import org.xipki.security.HashAlgo;
import org.xipki.security.IssuerHash;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "xi", name = "ocsp-status", description = "request certificate status")
@Service
public class OcspStatusAction extends BaseOcspStatusAction {

  @Reference
  private SecurityFactory securityFactory;

  @Override
  protected void checkParameters(X509Certificate respIssuer, List<BigInteger> serialNumbers,
      Map<BigInteger, byte[]> encodedCerts) throws Exception {
    ParamUtil.requireNonEmpty("serialNunmbers", serialNumbers);
  }

  @Override
  protected Object processResponse(OCSPResp response, X509Certificate respIssuer,
      IssuerHash issuerHash, List<BigInteger> serialNumbers,
      Map<BigInteger, byte[]> encodedCerts) throws Exception {
    ParamUtil.requireNonNull("response", response);
    ParamUtil.requireNonNull("issuerHash", issuerHash);
    ParamUtil.requireNonNull("serialNumbers", serialNumbers);

    BasicOCSPResp basicResp = OcspUtils.extractBasicOcspResp(response);

    boolean extendedRevoke = basicResp.getExtension(
        ObjectIdentifiers.id_pkix_ocsp_extendedRevoke) != null;

    SingleResp[] singleResponses = basicResp.getResponses();

    if (singleResponses == null || singleResponses.length == 0) {
      throw new CmdFailure("received no status from server");
    }

    final int n = singleResponses.length;
    if (n != serialNumbers.size()) {
      throw new CmdFailure("received status with " + n + " single responses from server, but "
          + serialNumbers.size() + " were requested");
    }

    Date[] thisUpdates = new Date[n];
    for (int i = 0; i < n; i++) {
      thisUpdates[i] = singleResponses[i].getThisUpdate();
    }

    // check the signature if available
    if (null == basicResp.getSignature()) {
      println("response is not signed");
    } else {
      X509CertificateHolder[] responderCerts = basicResp.getCerts();
      if (responderCerts == null || responderCerts.length < 1) {
        throw new CmdFailure("no responder certificate is contained in the response");
      }

      ResponderID respId = basicResp.getResponderId().toASN1Primitive();
      X500Name respIdByName = respId.getName();
      byte[] respIdByKey = respId.getKeyHash();

      X509CertificateHolder respSigner = null;
      for (X509CertificateHolder cert : responderCerts) {
        if (respIdByName != null) {
          if (cert.getSubject().equals(respIdByName)) {
            respSigner = cert;
          }
        } else {
          byte[] spkiSha1 = HashAlgo.SHA1.hash(
              cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
          if (Arrays.equals(respIdByKey, spkiSha1)) {
            respSigner = cert;
          }
        }

        if (respSigner != null) {
          break;
        }
      }

      if (respSigner == null) {
        throw new CmdFailure("no responder certificate match the ResponderId");
      }

      boolean validOn = true;
      for (Date thisUpdate : thisUpdates) {
        validOn = respSigner.isValidOn(thisUpdate);
        if (!validOn) {
          throw new CmdFailure("responder certificate is not valid on " + thisUpdate);
        }
      }

      if (validOn) {
        PublicKey responderPubKey = KeyUtil.generatePublicKey(respSigner.getSubjectPublicKeyInfo());
        ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(responderPubKey);
        boolean sigValid = basicResp.isSignatureValid(cvp);

        if (!sigValid) {
          throw new CmdFailure("response is equipped with invalid signature");
        }

        // verify the OCSPResponse signer
        if (respIssuer != null) {
          boolean certValid = true;
          X509Certificate jceRespSigner = X509Util.toX509Cert(respSigner.toASN1Structure());
          if (X509Util.issues(respIssuer, jceRespSigner)) {
            try {
              jceRespSigner.verify(respIssuer.getPublicKey());
            } catch (SignatureException ex) {
              certValid = false;
            }
          }

          if (!certValid) {
            throw new CmdFailure("response is equipped with valid signature but the"
                + " OCSP signer is not trusted");
          }
        } else {
          println("response is equipped with valid signature");
        } // end if(respIssuer)
      } // end if(validOn)

      if (verbose.booleanValue()) {
        println("responder is " + X509Util.getRfc4519Name(responderCerts[0].getSubject()));
      }
    } // end if

    for (int i = 0; i < n; i++) {
      if (n > 1) {
        println("---------------------------- " + i + "----------------------------");
      }
      SingleResp singleResp = singleResponses[i];
      CertificateStatus singleCertStatus = singleResp.getCertStatus();

      String status;
      if (singleCertStatus == null) {
        status = "good";
      } else if (singleCertStatus instanceof RevokedStatus) {
        RevokedStatus revStatus = (RevokedStatus) singleCertStatus;
        Date revTime = revStatus.getRevocationTime();
        Date invTime = null;
        Extension ext = singleResp.getExtension(Extension.invalidityDate);
        if (ext != null) {
          invTime = ASN1GeneralizedTime.getInstance(ext.getParsedValue()).getDate();
        }

        if (revStatus.hasRevocationReason()) {
          int reason = revStatus.getRevocationReason();
          if (extendedRevoke && reason == CrlReason.CERTIFICATE_HOLD.getCode()
              && revTime.getTime() == 0) {
            status = "unknown (RFC6960)";
          } else {
            status = StringUtil.concatObjects("revoked, reason = ",
                CrlReason.forReasonCode(reason).getDescription(), ", revocationTime = ", revTime,
                (invTime == null ? "" : ", invalidityTime = " + invTime));
          }
        } else {
          status = "revoked, no reason, revocationTime = " + revTime;
        }
      } else if (singleCertStatus instanceof UnknownStatus) {
        status = "unknown (RFC2560)";
      } else {
        status = "ERROR";
      }

      StringBuilder msg = new StringBuilder();

      CertificateID certId = singleResp.getCertID();
      HashAlgo hashAlgo = HashAlgo.getNonNullInstance(certId.getHashAlgOID());
      boolean issuerMatch = issuerHash.match(hashAlgo, certId.getIssuerNameHash(),
          certId.getIssuerKeyHash());
      BigInteger serialNumber = certId.getSerialNumber();

      msg.append("issuer matched: ").append(issuerMatch);
      msg.append("\nserialNumber: ").append(LogUtil.formatCsn(serialNumber));
      msg.append("\nCertificate status: ").append(status);

      if (verbose.booleanValue()) {
        msg.append("\nthisUpdate: ").append(singleResp.getThisUpdate());
        msg.append("\nnextUpdate: ").append(singleResp.getNextUpdate());

        Extension extension = singleResp.getExtension(
            ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
        if (extension != null) {
          msg.append("\nCertHash is provided:\n");
          ASN1Encodable extensionValue = extension.getParsedValue();
          CertHash certHash = CertHash.getInstance(extensionValue);
          ASN1ObjectIdentifier hashAlgOid = certHash.getHashAlgorithm().getAlgorithm();
          byte[] hashValue = certHash.getCertificateHash();

          msg.append("\tHash algo : ").append(hashAlgOid.getId()).append("\n");
          msg.append("\tHash value: ").append(Hex.encode(hashValue)).append("\n");

          if (encodedCerts != null) {
            byte[] encodedCert = encodedCerts.get(serialNumber);
            MessageDigest md = MessageDigest.getInstance(hashAlgOid.getId());
            byte[] expectedHashValue = md.digest(encodedCert);
            if (Arrays.equals(expectedHashValue, hashValue)) {
              msg.append("\tThis matches the requested certificate");
            } else {
              msg.append("\tThis differs from the requested certificate");
            }
          }
        } // end if (extension != null)

        extension = singleResp.getExtension(
            OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
        if (extension != null) {
          ASN1Encodable extensionValue = extension.getParsedValue();
          ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(extensionValue);
          msg.append("\nArchive-CutOff: ");
          msg.append(time.getTimeString());
        }

        AlgorithmIdentifier sigAlg = basicResp.getSignatureAlgorithmID();
        if (sigAlg == null) {
          msg.append(("\nresponse is not signed"));
        } else {
          String sigAlgName = AlgorithmUtil.getSignatureAlgoName(sigAlg);
          if (sigAlgName == null) {
            sigAlgName = "unknown";
          }
          msg.append("\nresponse is signed with ").append(sigAlgName);
        }

        // extensions
        msg.append("\nExtensions: ");

        List<?> extensionOids = basicResp.getExtensionOIDs();
        if (extensionOids == null || extensionOids.size() == 0) {
          msg.append("-");
        } else {
          int size = extensionOids.size();
          for (int j = 0; j < size; j++) {
            ASN1ObjectIdentifier extensionOid =
                (ASN1ObjectIdentifier) extensionOids.get(j);
            String name = EXTENSION_OIDNAME_MAP.get(extensionOid);
            if (name == null) {
              msg.append(extensionOid.getId());
            } else {
              msg.append(name);
            }
            if (j != size - 1) {
              msg.append(", ");
            }
          }
        }
      } // end if (verbose.booleanValue())

      println(msg.toString());
    } // end for
    println("");

    return null;
  } // method processResponse

}
