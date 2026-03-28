// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.pki.client;

import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.xipki.ocsp.client.RequestOptions;
import org.xipki.security.HashAlgo;
import org.xipki.security.OIDs;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.util.X509Util;
import org.xipki.shell.Completion;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.shell.xi.Completers;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.ReqRespDebug;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * OCSP client commands.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspCommands {
  @Command(name = "ocsp-status", description = "request certificate status",
      mixinStandardHelpOptions = true)
  static class OcspStatusCommand extends ShellBaseCommand {

    @Option(names = {"--issuer", "-i"}, required = true, description = "issuer certificate file")
    @Completion(FilePathCompleter.class)
    private String issuerCertFile;

    @Option(names = "--url", description = "OCSP responder URL")
    private String serverUrl;

    @Option(names = "--nonce", description = "use nonce")
    private Boolean useNonce = Boolean.FALSE;

    @Option(names = "--nonce-len", description = "nonce length in octets")
    private Integer nonceLen;

    @Option(names = "--allow-no-nonce-in-resp", description = "allow response without nonce")
    private Boolean allowNoNonceInResponse = Boolean.FALSE;

    @Option(names = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgoCompleter.class)
    private String hashAlgo = "SHA256";

    @Option(names = "--sig-alg", split = ",", description = "preferred signature algorithms")
    @Completion(Completers.SigAlgoCompleter.class)
    private List<String> prefSigAlgs;

    @Option(names = "--http-get", description = "use HTTP GET for small request")
    private Boolean useHttpGetForSmallRequest = Boolean.FALSE;

    @Option(names = "--sign", description = "sign request")
    private Boolean signRequest = Boolean.FALSE;

    @Option(names = "--req-out", description = "where to save the request")
    @Completion(FilePathCompleter.class)
    private String reqout;

    @Option(names = "--resp-out", description = "where to save the response")
    @Completion(FilePathCompleter.class)
    private String respout;

    @Option(names = {"--verbose", "-v"}, description = "show response details verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(names = "--hex", description = "serial number without prefix is hex number")
    private Boolean hex = Boolean.FALSE;

    @Option(names = {"--serial", "-s"}, description = "comma-separated serial numbers")
    private String serialNumberList;

    @Option(names = {"--cert", "-c"}, split = ",", description = "certificate files")
    @Completion(FilePathCompleter.class)
    private List<String> certFiles;

    @Override
    public void run() {
      try {
        if (StringUtil.isBlank(serialNumberList) && CollectionUtil.isEmpty(certFiles)) {
          throw new IOException("neither serial nor cert is set");
        }

        X509Cert issuerCert = X509Util.parseCert(new File(issuerCertFile));
        List<BigInteger> serials = new LinkedList<>();
        if (CollectionUtil.isNotEmpty(certFiles)) {
          String detectedUrl = null;
          for (String certFile : certFiles) {
            X509Cert cert = X509Util.parseCert(new File(certFile));
            if (!X509Util.issues(issuerCert, cert)) {
              throw new IOException("certificate " + certFile +
                  " is not issued by the given issuer");
            }
            if (StringUtil.isBlank(serverUrl)) {
              List<String> ocspUrls = extractOcspUrls(cert);
              if (CollectionUtil.isEmpty(ocspUrls)) {
                throw new IOException("could not extract OCSP responder URL");
              }
              String url = ocspUrls.get(0);
              if (detectedUrl != null && !detectedUrl.equals(url)) {
                throw new IOException("given certificates have different OCSP responder URLs");
              }
              detectedUrl = url;
            }
            serials.add(cert.serialNumber());
          }
          if (StringUtil.isBlank(serverUrl)) {
            serverUrl = detectedUrl;
          }
        } else {
          for (String token : serialNumberList.split("[, ]+")) {
            if (StringUtil.isBlank(token)) {
              continue;
            }
            serials.add(toBigInt(token, hex));
          }
        }

        if (StringUtil.isBlank(serverUrl)) {
          throw new IOException("could not get URL for the OCSP responder");
        }

        RequestOptions options = new RequestOptions();
        options.setUseNonce(useNonce);
        if (nonceLen != null) {
          options.setNonceLen(nonceLen);
        }
        options.setAllowNoNonceInResponse(allowNoNonceInResponse);
        options.setHashAlgorithm(HashAlgo.getInstance(hashAlgo));
        options.setSignRequest(signRequest);
        options.setUseHttpGetForRequest(useHttpGetForSmallRequest);
        if (CollectionUtil.isNotEmpty(prefSigAlgs)) {
          SignAlgo[] algos = new SignAlgo[prefSigAlgs.size()];
          for (int i = 0; i < algos.length; i++) {
            algos[i] = SignAlgo.getInstance(prefSigAlgs.get(i));
          }
          options.setPreferredSignatureAlgorithms(algos);
        }

        ReqRespDebug debug = null;
        if (StringUtil.isNotBlank(reqout) || StringUtil.isNotBlank(respout)) {
          debug = new ReqRespDebug(StringUtil.isNotBlank(reqout), StringUtil.isNotBlank(respout));
        }

        OCSPResp response;
        try {
          response = PkiClientRuntime.getOcspRequestor().ask(issuerCert,
              serials.toArray(new BigInteger[0]), new URL(serverUrl), options, debug);
        } finally {
          if (debug != null && debug.size() > 0) {
            ReqRespDebug.ReqRespPair reqResp = debug.get(0);
            if (StringUtil.isNotBlank(reqout) && reqResp.request() != null) {
              IoUtil.save(reqout, reqResp.request());
            }
            if (StringUtil.isNotBlank(respout) && reqResp.response() != null) {
              IoUtil.save(respout, reqResp.response());
            }
          }
        }

        if (response.getStatus() != 0) {
          println("response status: " + response.getStatus());
          return;
        }

        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        if (Boolean.TRUE.equals(verbose)) {
          println("producedAt=" + basicResp.getProducedAt());
          if (basicResp.getSignatureAlgorithmID() != null) {
            try {
              println("signatureAlg=" + SignAlgo.getInstance(
                  basicResp.getSignatureAlgorithmID()).jceName());
            } catch (Exception ex) {
              println("signatureAlg=" + basicResp.getSignatureAlgorithmID().getAlgorithm().getId());
            }
          }
        }

        SingleResp[] singleResponses = basicResp.getResponses();
        for (int i = 0; i < singleResponses.length; i++) {
          SingleResp singleResp = singleResponses[i];
          CertificateStatus status = singleResp.getCertStatus();
          String statusText;
          if (status == null) {
            statusText = "good";
          } else if (status instanceof RevokedStatus) {
            RevokedStatus revokedStatus = (RevokedStatus) status;
            statusText = "revoked";
            if (revokedStatus.hasRevocationReason()) {
              statusText += " reason=" + revokedStatus.getRevocationReason();
            }
            if (revokedStatus.getRevocationTime() != null) {
              statusText += " revocationTime=" + revokedStatus.getRevocationTime();
            }
          } else if (status instanceof UnknownStatus) {
            statusText = "unknown";
          } else {
            statusText = status.toString();
          }

          BigInteger sn = i < serials.size() ? serials.get(i) : null;
          StringBuilder msg = new StringBuilder("serial=")
              .append(sn == null ? "n/a" : sn.toString()).append(" status=").append(statusText);
          if (Boolean.TRUE.equals(verbose)) {
            msg.append(" thisUpdate=").append(singleResp.getThisUpdate());
            if (singleResp.getNextUpdate() != null) {
              msg.append(" nextUpdate=").append(singleResp.getNextUpdate());
            }
          }
          println(msg.toString());
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  private static List<String> extractOcspUrls(X509Cert cert) {
    byte[] extnValue = cert.getExtensionCoreValue(OIDs.Extn.authorityInfoAccess);
    return extnValue == null ? Collections.emptyList()
        : extractOcspUrls(AuthorityInformationAccess.getInstance(extnValue));
  }

  private static List<String> extractOcspUrls(AuthorityInformationAccess aia) {
    AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
    List<String> ocspUris = new ArrayList<>();
    for (AccessDescription accessDescription : accessDescriptions) {
      if (accessDescription.getAccessMethod().equals(OIDs.X509.id_ad_ocsp)) {
        GeneralName accessLocation = accessDescription.getAccessLocation();
        if (accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
          ocspUris.add(accessLocation.getName().toString());
        }
      }
    }
    return ocspUris;
  }

}
