// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.extra.http.HttpRespContent;
import org.xipki.util.extra.http.XiHttpClient;
import org.xipki.util.extra.misc.LogUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Iterator;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class ChallengeValidator implements Runnable {

  private static final TrustManager trustAll = new X509TrustManager() {

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  };

  private static final Logger LOG =
      LoggerFactory.getLogger(ChallengeValidator.class);

  private final AcmeRepo repo;

  public ChallengeValidator(AcmeRepo repo) {
    this.repo = Args.notNull(repo, "repo");
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      try {
        singleRun();
      } catch (Throwable t) {
        LogUtil.error(LOG, t, "expected error");
      }

      try {
        Thread.sleep(1000); // sleep for 1 second.
      } catch (InterruptedException e) {
      }
    }
  }

  public void singleRun() throws AcmeSystemException {
    Iterator<ChallId> challIds = repo.getChallengesToValidate();

    while (challIds.hasNext()) {
      ChallId challId = challIds.next();
      if (challId == null) {
        continue;
      }

      LOG.info("validate challenge {}", challId);

      AcmeChallenge2 chall2 = repo.getChallenge(challId);
      if (chall2 == null) {
        continue;
      }

      AcmeChallenge chall = chall2.getChallenge();
      String type = chall.getType();
      String receivedAuthorization = null;
      AcmeIdentifier identifier = chall2.getIdentifier();
      // boolean authorizationValid = false;

      if (LOG.isDebugEnabled()) {
        String host = identifier.getValue();
        if (host.startsWith("*.")) {
          host = host.substring(2);
        }

        try {
          InetAddress inetAddr = InetAddress.getByName(host);
          LOG.debug("type={}, host={}, InetAddress={}", type, host, inetAddr);
        } catch (UnknownHostException e) {
          LOG.debug("type={}, host={}, UnknownHostException", type, host);
        }
      }

      switch (type) {
        case AcmeConstants.HTTP_01: {
          String host = identifier.getValue();
          // host = "localhost:9081";
          String url = "http://" + host + "/.well-known/acme-challenge/" + chall.getToken();
          try {
            XiHttpClient client = new XiHttpClient();
            HttpRespContent authzResp = client.httpGet(url);
            receivedAuthorization = new String(authzResp.getContent(),
                StandardCharsets.UTF_8);
          } catch (IOException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }
          break;
        }
        case AcmeConstants.TLS_ALPN_01: {
          Certificate[] certs = null;
          try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustAll}, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket)
                factory.createSocket(identifier.getValue(), 443)) {
              SSLParameters params = socket.getSSLParameters();
              params.setApplicationProtocols(new String[]{"acme-tls/1.0"});
              params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
              socket.setSSLParameters(params);

              SSLSession session = socket.getSession();
              certs = session.getPeerCertificates();
            }
          } catch (NoSuchAlgorithmException | IOException
                   | KeyManagementException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }

          boolean match = certs != null && certs.length > 0
              && certs[0] instanceof X509Certificate;
          // check the SAN
          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            byte[] extnValue = cert.getExtensionValue(
                OIDs.Extn.subjectAlternativeName.getId());
            byte[] octets = ASN1OctetString.getInstance(extnValue).getOctets();
            GeneralNames generalNames = GeneralNames.getInstance(octets);
            GeneralName[] names = generalNames.getNames();
            match = (names != null
                    && names.length == 1
                    && names[0].getTagNo() == GeneralName.dNSName);
            if (match) {
              String sanValue = ASN1IA5String.getInstance(
                                  names[0].getName()).getString();
              match = identifier.getValue().equals(sanValue);
            }
          }

          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            // check the critical extension id_pe_acmeIdentifier
            match = cert.getCriticalExtensionOIDs().contains(
                      OIDs.ACME.id_pe_acmeIdentifier.getId());
            if (match) {
              byte[] extnValue = cert.getExtensionValue(
                  OIDs.ACME.id_pe_acmeIdentifier.getId());
              byte[] octets = ASN1OctetString.getInstance(extnValue)
                              .getOctets();
              byte[] value = ASN1OctetString.getInstance(octets).getOctets();
              receivedAuthorization = Base64.getUrlNoPaddingEncoder()
                  .encodeToString(value);
            }
          }
          break;
        }
        case AcmeConstants.DNS_01: {
          String host = identifier.getValue();
          if (host.startsWith("*.")) {
            host = host.substring(2);
          }

          LOG.debug("dns-01: host='{}'", identifier.getValue());

          String acmeDomain = "_acme-challenge." + host;
          Record[] records = null;
          try {
            records = new Lookup(acmeDomain, Type.TXT).run();
          } catch (TextParseException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }

          String expectedName = acmeDomain + ".";
          if (records != null) {
            for (Record record : records) {
              TXTRecord txt = (TXTRecord) record;
              String name = txt.getName().toString();
              if (!expectedName.equals(name)) {
                continue;
              }

              receivedAuthorization = txt.getStrings().get(0);
            }
          }
          break;
        }
        default: {
          throw new RuntimeException("should not reach here, unknown " +
              "challenge type '" + type + "'");
        }
      }

      boolean authorizationValid = false;
      if (receivedAuthorization != null) {
        authorizationValid = chall.getExpectedAuthorization()
            .equals(receivedAuthorization.trim());
      }

      if (authorizationValid) {
        LOG.info("validated challenge {}/{} for identifier {}/{}",
            chall.getType(), challId, identifier.getType(),
            identifier.getValue());
        chall.setValidated(Instant.now().truncatedTo(ChronoUnit.SECONDS));
        chall.setStatus(ChallengeStatus.valid);
      } else {
        LOG.warn("validation failed for challenge {}/{} for identifier " +
                "{}/{}: received='{}', expected='{}'",
            chall.getType(), challId, identifier.getType(),
            identifier.getValue(), receivedAuthorization,
            chall.getExpectedAuthorization());
        chall.setStatus(ChallengeStatus.invalid);
      }

      if (chall.getAuthz() != null && chall.getAuthz().getOrder() != null) {
        repo.flushOrderIfNotCached(chall.getAuthz().getOrder());
      }
    }

  }

  public void close() {
    stopMe = true;
  }

}
