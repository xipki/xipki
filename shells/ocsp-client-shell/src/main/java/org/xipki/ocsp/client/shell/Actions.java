// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.client.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.xipki.ocsp.client.OcspRequestor;
import org.xipki.ocsp.client.OcspResponseException;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.security.*;
import org.xipki.security.util.KeyUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.*;
import org.xipki.util.ReqRespDebug.ReqRespPair;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.*;

/**
 * OCSP client actions.
 *
 * @author Lijun Liao (xipki)
 */
public class Actions {

  public abstract static class BaseOcspStatusAction extends CommonOcspStatusAction {

    private static class BigIntegerRange {
      private final BigInteger from;
      private final BigInteger to;
      private final BigInteger diff;

      BigIntegerRange(BigInteger from, BigInteger to) {
        if (from.compareTo(to) > 0) {
          throw new IllegalArgumentException("from (" + from + ") may not be larger than to (" + to + ")");
        }
        this.from = from;
        this.to = to;
        this.diff = to.subtract(from);
      }

      boolean isInRange(BigInteger num) {
        return num.compareTo(from) >= 0 && num.compareTo(to) <= 0;
      }

    } // class BigIntegerRange

    protected static final Map<ASN1ObjectIdentifier, String> EXTENSION_OIDNAME_MAP = new HashMap<>();

    @Option(name = "--verbose", aliases = "-v", description = "show status verbosely")
    protected Boolean verbose = Boolean.FALSE;

    @Option(name = "--resp-issuer", description = "certificate file of the responder's issuer")
    @Completion(FileCompleter.class)
    private String respIssuerFile;

    @Option(name = "--url", description = "OCSP responder URL")
    private String serverUrl;

    @Option(name = "--req-out", description = "where to save the request")
    @Completion(FileCompleter.class)
    private String reqout;

    @Option(name = "--resp-out", description = "where to save the response")
    @Completion(FileCompleter.class)
    private String respout;

    @Option(name = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(name = "--serial", aliases = "-s",
        description = "comma-separated serial numbers or ranges (like 1,3,6-10)\n"
            + "(at least one of serial and cert must be specified)")
    private String serialNumberList;

    @Option(name = "--cert", aliases = "-c", multiValued = true, description = "certificate files")
    @Completion(FileCompleter.class)
    private List<String> certFiles;

    @Option(name = "--ac", description = "the certificates are attribute certificates")
    @Completion(FileCompleter.class)
    private Boolean isAttrCert = Boolean.FALSE;

    @Reference
    private OcspRequestor requestor;

    static {
      EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, "ArchiveCutoff");
      EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_crl, "CrlID");
      EXTENSION_OIDNAME_MAP.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, "Nonce");
      EXTENSION_OIDNAME_MAP.put(ObjectIdentifiers.Extn.id_pkix_ocsp_extendedRevoke, "ExtendedRevoke");
    }

    /**
     * Check whether the parameters are valid.
     *
     * @param respIssuer
     *          Expected responder issuer. Could be {@code null}.
     * @param serialNumbers
     *          Expected serial numbers. Must not be {@code null}.
     * @param encodedCerts
     *          Map of serial number and the corresponding certificate. Could be {@code null}.
     * @throws Exception
     *           if checking failed.
     */
    protected abstract void checkParameters(
        X509Cert respIssuer, List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception;

    /**
     * Check whether the response has the expected issuer, certificate serial numbers and
     * for the given encoded certificates.
     *
     * @param response
     *          OCSP response. Must not be {@code null}.
     * @param respIssuer
     *          Expected responder issuer. Could be {@code null}.
     * @param issuerHash
     *          Expected issuer hash. Must not be {@code null}.
     * @param serialNumbers
     *          Expected serial numbers. Must not be {@code null}.
     * @param encodedCerts
     *          Map of serial number and the corresponding certificate. Could be {@code null}.
     * @throws Exception
     *           if processing response failed.
     */
    protected abstract void processResponse(
        OCSPResp response, X509Cert respIssuer, IssuerHash issuerHash,
        List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception;

    @Override
    protected final Object execute0() throws Exception {
      if (StringUtil.isBlank(serialNumberList) && isEmpty(certFiles)) {
        throw new IllegalCmdParamException("Neither serialNumbers nor certFiles is set");
      }

      X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));

      Map<BigInteger, byte[]> encodedCerts = null;
      List<BigInteger> sns = new LinkedList<>();

      if (isNotEmpty(certFiles)) {
        encodedCerts = new HashMap<>(certFiles.size());
        String ocspUrl = null;
        X500Name issuerX500Name = null;

        for (String certFile : certFiles) {
          BigInteger sn;
          List<String> ocspUrls;

          if (isAttrCert) {
            if (issuerX500Name == null) {
              issuerX500Name = issuerCert.getSubject();
            }

            X509AttributeCertificateHolder cert = new X509AttributeCertificateHolder(IoUtil.read(certFile));
            // no signature validation
            AttributeCertificateIssuer reqIssuer = cert.getIssuer();
            if (reqIssuer != null && issuerX500Name != null) {
              if (!issuerX500Name.equals(reqIssuer.getNames()[0])) {
                throw new IllegalCmdParamException("certificate " + certFile + " is not issued by the given issuer");
              }
            }

            ocspUrls = extractOcspUrls(cert);
            sn = cert.getSerialNumber();
          } else {
            X509Cert cert = X509Util.parseCert(new File(certFile));
            if (!X509Util.issues(issuerCert, cert)) {
              throw new IllegalCmdParamException("certificate " + certFile + " is not issued by the given issuer");
            }
            ocspUrls = extractOcspUrls(cert);
            sn = cert.getSerialNumber();
          }

          if (isBlank(serverUrl)) {
            if (CollectionUtil.isEmpty(ocspUrls)) {
              throw new IllegalCmdParamException("could not extract OCSP responder URL");
            } else {
              String url = ocspUrls.get(0);
              if (ocspUrl != null && !ocspUrl.equals(url)) {
                throw new IllegalCmdParamException(
                    "given certificates have different OCSP responder URL in certificate");
              } else {
                ocspUrl = url;
              }
            }
          } // end if

          sns.add(sn);
          encodedCerts.put(sn, IoUtil.read(certFile));
        } // end for

        if (isBlank(serverUrl)) {
          serverUrl = ocspUrl;
        }
      } else {
        StringTokenizer st = new StringTokenizer(serialNumberList, ", ");
        while (st.hasMoreTokens()) {
          String token = st.nextToken();
          StringTokenizer st2 = new StringTokenizer(token, "-");
          BigInteger from = toBigInt(st2.nextToken(), hex);
          BigInteger to = st2.hasMoreTokens() ? toBigInt(st2.nextToken(), hex) : null;
          if (to == null) {
            sns.add(from);
          } else {
            BigIntegerRange range = new BigIntegerRange(from, to);
            if (range.diff.compareTo(BigInteger.valueOf(10)) > 0) {
              throw new IllegalCmdParamException("to many serial numbers");
            }

            BigInteger sn = range.from;
            while (range.isInRange(sn)) {
              sns.add(sn);
              sn = sn.add(BigInteger.ONE);
            }
          }
        }
      }

      if (isBlank(serverUrl)) {
        throw new IllegalCmdParamException("could not get URL for the OCSP responder");
      }

      X509Cert respIssuer = null;
      if (respIssuerFile != null) {
        respIssuer = X509Util.parseCert(new File(respIssuerFile));
      }

      URL serverUrlObj = new URL(serverUrl);
      RequestOptions options = getRequestOptions();
      checkParameters(respIssuer, sns, encodedCerts);
      boolean saveReq = isNotBlank(reqout);
      boolean saveResp = isNotBlank(respout);
      ReqRespDebug debug = null;
      if (saveReq || saveResp) {
        debug = new ReqRespDebug(saveReq, saveResp);
      }

      IssuerHash issuerHash = new IssuerHash(options.getHashAlgorithm(), issuerCert);
      OCSPResp response;
      try {
        response = requestor.ask(issuerCert, sns.toArray(new BigInteger[0]), serverUrlObj, options, debug);
      } finally {
        if (debug != null && debug.size() > 0) {
          ReqRespPair reqResp = debug.get(0);
          if (saveReq) {
            byte[] bytes = reqResp.getRequest();
            if (bytes != null) {
              IoUtil.save(reqout, bytes);
            }
          }

          if (saveResp) {
            byte[] bytes = reqResp.getResponse();
            if (bytes != null) {
              IoUtil.save(respout, bytes);
            }
          }
        } // end if
      } // end finally

      processResponse(response, respIssuer, issuerHash, sns, encodedCerts);
      return null;
    } // method execute0

    public static List<String> extractOcspUrls(X509Cert cert) {
      byte[] extnValue = cert.getExtensionCoreValue(Extension.authorityInfoAccess);
      return (extnValue == null) ? Collections.emptyList()
          : extractOcspUrls(AuthorityInformationAccess.getInstance(extnValue));
    } // method extractOcspUrls

    public static List<String> extractOcspUrls(X509AttributeCertificateHolder cert) {
      byte[] extValue = X509Util.getCoreExtValue(cert.getExtensions(), Extension.authorityInfoAccess);
      return (extValue == null) ? Collections.emptyList()
          : extractOcspUrls(AuthorityInformationAccess.getInstance(extValue));
    } // method extractOcspUrls

    public static List<String> extractOcspUrls(AuthorityInformationAccess aia) {
      AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
      List<AccessDescription> ocspAccessDescriptions = new LinkedList<>();
      for (AccessDescription accessDescription : accessDescriptions) {
        if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp)) {
          ocspAccessDescriptions.add(accessDescription);
        }
      }

      final int n = ocspAccessDescriptions.size();
      List<String> ocspUris = new ArrayList<>(n);
      for (AccessDescription ocspAccessDescription : ocspAccessDescriptions) {
        GeneralName accessLocation = ocspAccessDescription.getAccessLocation();
        if (accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
          ocspUris.add(((ASN1String) accessLocation.getName()).getString());
        }
      }

      return ocspUris;
    } // method extractOcspUrls

  } // class BaseOcspStatusAction

  public abstract static class CommonOcspStatusAction extends XiAction {

    @Option(name = "--issuer", aliases = "-i", required = true, description = "issuer certificate file")
    @Completion(FileCompleter.class)
    protected String issuerCertFile;

    @Option(name = "--nonce", description = "use nonce")
    protected Boolean usenonce = Boolean.FALSE;

    @Option(name = "--nonce-len", description = "nonce length in octects")
    protected Integer nonceLen;

    @Option(name = "--allow-no-nonce-in-resp",
        description = "allow response without nonce, only applied if request has nonce.")
    protected Boolean allowNoNonceInResponse = Boolean.FALSE;

    @Option(name = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--sig-alg", multiValued = true, description = "comma-separated preferred signature algorithms")
    @Completion(Completers.SigAlgCompleter.class)
    protected List<String> prefSigAlgs;

    @Option(name = "--http-get", description = "use HTTP GET for small request")
    protected Boolean useHttpGetForSmallRequest = Boolean.FALSE;

    @Option(name = "--sign", description = "sign request")
    protected Boolean signRequest = Boolean.FALSE;

    protected RequestOptions getRequestOptions() throws Exception {
      RequestOptions options = new RequestOptions();
      options.setUseNonce(usenonce);
      if (nonceLen != null) {
        options.setNonceLen(nonceLen);
      }
      options.setAllowNoNonceInResponse(allowNoNonceInResponse);
      options.setHashAlgorithm(HashAlgo.getInstance(hashAlgo));
      options.setSignRequest(signRequest);
      options.setUseHttpGetForRequest(useHttpGetForSmallRequest);

      if (isNotEmpty(prefSigAlgs)) {
        SignAlgo[] algos = new SignAlgo[prefSigAlgs.size()];
        for (int i = 0; i < algos.length; i++) {
          algos[i] = SignAlgo.getInstance(prefSigAlgs.get(i));
        }

        options.setPreferredSignatureAlgorithms(algos);
      }
      return options;
    } // method getRequestOptions

  } // class CommonOcspStatusAction

  @Command(scope = "xi", name = "ocsp-status", description = "request certificate status")
  @Service
  public static class OcspStatus extends BaseOcspStatusAction {

    @Reference
    private SecurityFactory securityFactory;

    @Option(name = "--quiet", description = "Do not throw error if OCSP status is not 'OK'")
    protected Boolean quiet = Boolean.FALSE;

    @Override
    protected void checkParameters(
        X509Cert respIssuer, List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception {
      Args.notEmpty(serialNumbers, "serialNumbers");
    }

    @Override
    protected void processResponse(
        OCSPResp response, X509Cert respIssuer, IssuerHash issuerHash,
        List<BigInteger> serialNumbers, Map<BigInteger, byte[]> encodedCerts)
        throws Exception {
      Args.notNull(response, "response");
      Args.notNull(issuerHash, "issuerHash");
      Args.notNull(serialNumbers, "serialNumbers");

      int statusCode = response.getStatus();
      if (statusCode != 0) {
        if (quiet) {
          println(new OcspResponseException.Unsuccessful(statusCode).statusText());
          return;
        } else {
          throw new OcspResponseException.Unsuccessful(statusCode);
        }
      }

      BasicOCSPResp basicResp;
      try {
        basicResp = (BasicOCSPResp) response.getResponseObject();
      } catch (OCSPException ex) {
        throw new OcspResponseException.InvalidResponse(ex.getMessage(), ex);
      }

      boolean extendedRevoke = basicResp.getExtension(ObjectIdentifiers.Extn.id_pkix_ocsp_extendedRevoke) != null;

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
            byte[] spkiSha1 = HashAlgo.SHA1.hash(cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
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

        for (Date thisUpdate : thisUpdates) {
          if (!respSigner.isValidOn(thisUpdate)) {
            throw new CmdFailure("responder certificate is not valid on " + thisUpdate);
          }
        }

        PublicKey responderPubKey = KeyUtil.generatePublicKey(respSigner.getSubjectPublicKeyInfo());
        ContentVerifierProvider cvp = securityFactory.getContentVerifierProvider(responderPubKey);
        boolean sigValid = basicResp.isSignatureValid(cvp);

        if (!sigValid) {
          throw new CmdFailure("response is equipped with invalid signature");
        }

        // verify the OCSPResponse signer
        if (respIssuer != null) {
          boolean certValid = true;
          X509Cert respSigner2 = new X509Cert(respSigner);
          if (X509Util.issues(respIssuer, respSigner2)) {
            try {
              respSigner2.verify(respIssuer.getPublicKey());
            } catch (SignatureException ex) {
              certValid = false;
            }
          }

          if (!certValid) {
            throw new CmdFailure("response is equipped with valid signature but the OCSP signer is not trusted");
          }
        } else {
          println("response is equipped with valid signature");
        } // end if(respIssuer)

        if (verbose) {
          println("responder is " + X509Util.x500NameText(responderCerts[0].getSubject()));
        }
      } // end if

      println("produced at " + basicResp.getProducedAt());

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
          Extension ext = singleResp.getExtension(Extension.invalidityDate);
          Date invTime = (ext == null) ? null : ASN1GeneralizedTime.getInstance(ext.getParsedValue()).getDate();

          if (revStatus.hasRevocationReason()) {
            int reason = revStatus.getRevocationReason();
            if (extendedRevoke && reason == CrlReason.CERTIFICATE_HOLD.getCode() && revTime.getTime() == 0) {
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
        HashAlgo hashAlgo = HashAlgo.getInstance(certId.getHashAlgOID());
        boolean issuerMatch = issuerHash.match(hashAlgo, certId.getIssuerNameHash(), certId.getIssuerKeyHash());
        BigInteger serialNumber = certId.getSerialNumber();

        msg.append("issuer matched: ").append(issuerMatch);
        msg.append("\nserialNumber: ").append(LogUtil.formatCsn(serialNumber));
        msg.append("\nCertificate status: ").append(status);

        if (verbose) {
          msg.append("\nthisUpdate: ").append(singleResp.getThisUpdate());
          msg.append("\nnextUpdate: ").append(singleResp.getNextUpdate());

          Extension extension = singleResp.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash);
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

          extension = singleResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
          if (extension != null) {
            ASN1Encodable extensionValue = extension.getParsedValue();
            msg.append("\nArchive-CutOff: ");
            msg.append(ASN1GeneralizedTime.getInstance(extensionValue).getTimeString());
          }

          AlgorithmIdentifier sigAlgo = basicResp.getSignatureAlgorithmID();
          if (sigAlgo == null) {
            msg.append(("\nresponse is not signed"));
          } else {
            String sigAlgoName;
            try {
              sigAlgoName = SignAlgo.getInstance(sigAlgo).getJceName();
            } catch (NoSuchAlgorithmException ex) {
              sigAlgoName = "unknown";
            }
            msg.append("\nresponse is signed with ").append(sigAlgoName);
          }

          // extensions
          msg.append("\nExtensions: ");

          List<?> extensionOids = basicResp.getExtensionOIDs();
          if (extensionOids == null || extensionOids.size() == 0) {
            msg.append("-");
          } else {
            int size = extensionOids.size();
            for (int j = 0; j < size; j++) {
              ASN1ObjectIdentifier extensionOid = (ASN1ObjectIdentifier) extensionOids.get(j);
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
    } // method processResponse

  } // class OcspStatus

}
