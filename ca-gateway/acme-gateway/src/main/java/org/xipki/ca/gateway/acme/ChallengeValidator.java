package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.jose4j.base64url.Base64Url;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.xipki.ca.gateway.acme.type.AuthzStatus;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.ca.gateway.acme.type.OrderStatus;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.LogUtil;
import org.xipki.util.http.HttpRespContent;
import org.xipki.util.http.XiHttpClient;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;

public class ChallengeValidator implements Runnable {

  private static final TrustManager trustAll = new X509TrustManager() {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      System.out.println("trust checkClientTrusted");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      System.out.println("trust checkServerTrusted");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  };

  private static final Logger LOG = LoggerFactory.getLogger(CertEnroller.class);

  private final AcmeRepo acmeRepo;

  public ChallengeValidator(AcmeRepo acmeRepo) {
    this.acmeRepo = Args.notNull(acmeRepo, "acmeRepo");
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      Iterator<String> orderLabels = acmeRepo.getOrdersToValidate();
      if (!orderLabels.hasNext()) {
        try {
          Thread.sleep(1000); // sleep for 1 second.
        } catch (InterruptedException e) {
        }
        continue;
      }

      while (orderLabels.hasNext()) {
        String orderLabel = orderLabels.next();
        LOG.debug("validate challenge for order {}", orderLabel);
        if (orderLabel == null) {
          continue;
        }

        AcmeOrder order = acmeRepo.getOrder(orderLabel);
        if (order == null) {
          continue;
        }

        AcmeAuthz[] authzs = order.getAuthzs();
        for (AcmeAuthz authz : authzs) {
          AcmeChallenge chall = null;
          for (AcmeChallenge chall0 : authz.getChallenges()) {
            if (chall0.getStatus() == ChallengeStatus.processing) {
              chall = chall0;
              break;
            }
          }

          if (chall == null) {
            continue;
          }

          String type = chall.getType();
          String receivedAuthorization = null;
          // boolean authorizationValid = false;

          switch (type) {
            case AcmeConstants.HTTP_01: {
              try {
                org.xipki.util.http.XiHttpClient client = new XiHttpClient();
                String url = "http://" + authz.getIdentifier().getValue() + "/.well-known/acme-challenge/"
                              + chall.getToken();
                HttpRespContent authzResp = client.httpGet(url);
                receivedAuthorization = new String(authzResp.getContent(), StandardCharsets.UTF_8);
              } catch (IOException ex) {
                String message = "error while validation challenge"; // TODO: more info
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
                SSLSocket socket = (SSLSocket) factory.createSocket("github.com", 443);
                SSLParameters params = socket.getSSLParameters();
                params.setApplicationProtocols(new String[]{"acme-tls/1.0"});
                params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
                socket.setSSLParameters(params);

                //socket.startHandshake();
                SSLSession session = socket.getSession();
                certs = session.getPeerCertificates();
              } catch (NoSuchAlgorithmException | IOException | KeyManagementException ex) {
                String message = "error while validation challenge"; // TODO: more info
                LogUtil.error(LOG, ex, message);
              }

              boolean match = certs != null && certs.length > 0 && certs[0] instanceof X509Certificate;
              // check the SAN
              if (match) {
                X509Certificate cert = (X509Certificate) certs[0];
                byte[] extnValue = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
                byte[] octets = ASN1OctetString.getInstance(extnValue).getOctets();
                GeneralNames generalNames = GeneralNames.getInstance(octets);
                GeneralName[] names = generalNames.getNames();
                match = (names != null && names.length == 1 && names[0].getTagNo() == GeneralName.dNSName);
                if (match) {
                  String sanValue = ASN1IA5String.getInstance(names[0].getName()).getString();
                  match = authz.getIdentifier().getValue().equals(sanValue);
                }
              }

              if (match) {
                X509Certificate cert = (X509Certificate) certs[0];
                // check the critical extension id_pe_acmeIdentifier
                match = cert.getCriticalExtensionOIDs().contains(AcmeConstants.id_pe_acmeIdentifier);
                if (match) {
                  byte[] extnValue = cert.getExtensionValue(AcmeConstants.id_pe_acmeIdentifier);
                  byte[] octets = ASN1OctetString.getInstance(extnValue).getOctets();
                  byte[] value = ASN1OctetString.getInstance(octets).getOctets();
                  receivedAuthorization = Base64Url.encode(value);
                }
              }
              break;
            }
            case AcmeConstants.DNS_01: {
              String host = authz.getIdentifier().getValue();
              if (host.startsWith("*.")) {
                host = host.substring(2);
              }

              Record[] records = null;
              try {
                records = new Lookup(host, Type.TXT).run();
              } catch (TextParseException ex) {
                String message = "error validating challenge"; // TODO: more info
                LogUtil.error(LOG, ex, message);
              }

              String expectedName = "_acme-challenge." + host + ".";
              if (records != null) {
                for (int i = 0; i < records.length; i++) {
                  TXTRecord txt = (TXTRecord) records[i];
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
              throw new RuntimeException("should not reach here, unknown challenge type '" + type + "'");
            }
          }

          boolean authorizationValid = chall.getExpectedAuthorization().equals(receivedAuthorization);
          if (authorizationValid) {
            LOG.info("validated challenge {}/{} for identifier {}/{}", chall.getType(), chall.getLabel(),
                authz.getIdentifier().getType(), authz.getIdentifier().getValue());
            chall.setValidated(Instant.now());
            chall.setStatus(ChallengeStatus.valid);
            authz.setStatus(AuthzStatus.valid);
          } else {
            LOG.warn("validation failed for challenge {}/{} for identifier {}/{}: received='{}', expected='{}'",
                chall.getType(), chall.getLabel(), authz.getIdentifier().getType(), authz.getIdentifier().getValue(),
                receivedAuthorization, chall.getExpectedAuthorization());
            chall.setStatus(ChallengeStatus.invalid);
            authz.setStatus(AuthzStatus.deactivated);
          }
        }

        boolean allAuthzsValidated = true;
        for (AcmeAuthz authz : authzs) {
          if (authz.getStatus() != AuthzStatus.valid) {
            allAuthzsValidated = false;
            break;
          }
        }

        if (allAuthzsValidated) {
          order.setStatus(OrderStatus.ready);
        }
      }
    }
  }

  public void close() {
    stopMe = true;
  }

}
