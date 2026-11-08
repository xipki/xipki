// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkix.asn1.x509.GeneralName;
import org.xipki.pkix.asn1.x509.GeneralNames;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.oid.ExtensionOIDs;
import org.xipki.codec.asn1.oid.MiscOIDs;
import org.xipki.acme.type.ChallengeStatus;
import org.xipki.codec.util.Args;
import org.xipki.codec.Base64;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.misc.LogUtil;
import org.xipki.util.io.XipkiIoUtil;
import org.xipki.dns.DnsClient;
import org.xipki.dns.DnsRecord;
import org.xipki.dns.NetDnsTransport;
import org.xipki.dns.dnssec.DnssecValidator;
import org.xipki.dns.dnssec.TrustAnchorsFile;
import org.xipki.acme.AcmeChallenge;
import org.xipki.acme.AcmeChallenge2;
import org.xipki.acme.AcmeConf;
import org.xipki.acme.AcmeConstants;
import org.xipki.acme.AcmeIdentifier;
import org.xipki.acme.AcmeRepo;
import org.xipki.acme.AcmeSystemException;
import org.xipki.acme.ChallId;
import org.xipki.acme.Http01Client;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Challenge Validator.
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

  private static final Logger LOG = LoggerFactory.getLogger(ChallengeValidator.class);

  private static final long TRUST_ANCHORS_CHECK_INTERVAL_MS = 60_000;

  // RFC 8737, section 6.2
  private static final String ACME_TLS_1_PROTOCOL = "acme-tls/1";

  private final AcmeRepo repo;

  private final DnsClient dnsClient;

  // resolves the hosts of http-01 and tls-alpn-01, without DNSSEC validation
  private final DnsClient addressClient;

  private final DnssecValidator dnssecValidator;

  private final TrustAnchorsFile trustAnchorsFile;

  private long nextTrustAnchorsCheck;

  private final boolean allowPrivateChallengeTargets;

  private final SSLSocketFactory trustAllSocketFactory;

  private final Http01Client http01Client;

  public ChallengeValidator(AcmeRepo repo, AcmeConf.Acme conf) throws InvalidConfException {
    this.repo = Args.notNull(repo, "repo");
    Args.notNull(conf, "conf");
    List<InetSocketAddress> dnsServers;
    try {
      dnsServers = NetDnsTransport.parseServers(conf.dnsResolvers());
    } catch (IOException ex) {
      throw new InvalidConfException("could not initialize DNS resolver", ex);
    }

    NetDnsTransport transport = new NetDnsTransport(dnsServers, conf.dnssecValidation(),
        NetDnsTransport.DEFAULT_TIMEOUT_MS);

    if (conf.dnssecValidation()) {
      this.trustAnchorsFile = new TrustAnchorsFile(
          Path.of(XipkiIoUtil.expandFilepath(conf.dnssecTrustAnchorsFile(), true)));
      try {
        this.dnssecValidator = new DnssecValidator(transport, trustAnchorsFile.load(),
            Clock.systemUTC());
      } catch (IOException | IllegalArgumentException ex) {
        throw new InvalidConfException(
            "could not load DNSSEC trust anchors from " + conf.dnssecTrustAnchorsFile(), ex);
      }
      this.nextTrustAnchorsCheck = System.currentTimeMillis() + TRUST_ANCHORS_CHECK_INTERVAL_MS;
    } else {
      this.trustAnchorsFile = null;
      this.dnssecValidator = null;
    }
    this.dnsClient = new DnsClient(transport, dnssecValidator);
    // Without DNSSEC (CD=0), a validating resolver still rejects bogus addresses.
    this.addressClient = dnssecValidator == null ? dnsClient
        : new DnsClient(new NetDnsTransport(dnsServers, false,
            NetDnsTransport.DEFAULT_TIMEOUT_MS), null);
    this.allowPrivateChallengeTargets = conf.allowPrivateChallengeTargets();

    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new TrustManager[]{trustAll}, null);
      this.trustAllSocketFactory = sslContext.getSocketFactory();
    } catch (NoSuchAlgorithmException | KeyManagementException ex) {
      throw new InvalidConfException("could not initialize SSLContext", ex);
    }

    this.http01Client = new Http01Client(this::resolveChallengeHost, trustAllSocketFactory);
  }

  private boolean stopMe;

  @Override
  public void run() {
    while (!stopMe) {
      reloadTrustAnchorsIfChanged();
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

      AcmeChallenge chall = chall2.challenge();
      String type = chall.type();
      String receivedAuthorization = null;
      AcmeIdentifier identifier = chall2.identifier();
      // boolean authorizationValid = false;

      switch (type) {
        case AcmeConstants.HTTP_01: {
          String host = identifier.value();
          try {
            byte[] content = http01Client.get(host, "/.well-known/acme-challenge/" + chall.token());
            receivedAuthorization = new String(content, StandardCharsets.UTF_8);
          } catch (IOException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }
          break;
        }
        case AcmeConstants.TLS_ALPN_01: {
          Certificate[] certs = null;
          String host = identifier.value();
          try {
            InetAddress[] addresses = resolveChallengeHost(host);
            Socket plainSocket = Http01Client.connect(addresses, 443,
                Http01Client.CONNECT_TIMEOUT_MS);
            try (SSLSocket socket = (SSLSocket) trustAllSocketFactory.createSocket(
                plainSocket, host, 443, true)) {
              socket.setSoTimeout(Http01Client.CONNECT_TIMEOUT_MS);
              SSLParameters params = socket.getSSLParameters();
              params.setApplicationProtocols(new String[]{ACME_TLS_1_PROTOCOL});
              params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
              params.setServerNames(Collections.singletonList(new SNIHostName(host)));
              socket.setSSLParameters(params);
              socket.startHandshake();

              String negotiatedProtocol = socket.getApplicationProtocol();
              if (ACME_TLS_1_PROTOCOL.equals(negotiatedProtocol)) {
                SSLSession session = socket.getSession();
                certs = session.getPeerCertificates();
              } else {
                LOG.warn("tls-alpn-01: negotiated ALPN protocol '{}' instead of '{}' for {}",
                    negotiatedProtocol, ACME_TLS_1_PROTOCOL, host);
              }
            } catch (IOException | RuntimeException ex) {
              plainSocket.close();
              throw ex;
            }
          } catch (IOException | IllegalArgumentException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }

          boolean match = certs != null && certs.length > 0 && certs[0] instanceof X509Certificate;
          // check the SAN
          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            byte[] extnValue = cert.getExtensionValue(ExtensionOIDs.subjectAlternativeName.getId());

            GeneralNames generalNames;

            try {
              byte[] octets = Asn1OctetString.fromEncoded(extnValue).getOctets();
              generalNames = GeneralNames.fromEncoded(octets);

              match = generalNames.size() == 1
                        && generalNames.get(0).getTagNo() == GeneralName.tag_dNSName;
              if (match) {
                String sanValue = generalNames.get(0).dNSName();
                match = identifier.value().equalsIgnoreCase(sanValue);
              }
            } catch (CodecException ex) {
              String message =  "error while validating challenge " + challId +
                                " for identifier " + identifier;
              LogUtil.error(LOG, ex, message);
              match = false;
            }
          }

          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            // check the critical extension id_pe_acmeIdentifier
            var criticalExtensionOids = cert.getCriticalExtensionOIDs();
            match = criticalExtensionOids != null
                && criticalExtensionOids.contains(MiscOIDs.id_pe_acmeIdentifier.getId());
            if (match) {
              byte[] extnValue = cert.getExtensionValue(MiscOIDs.id_pe_acmeIdentifier.getId());
              if (extnValue != null) {
                byte[] octets = null;
                try {
                  octets = Asn1OctetString.fromEncoded(extnValue).getOctets();
                } catch (CodecException ex) {
                  // do nothing
                }

                if (octets != null) {
                  byte[] value = null;
                  try {
                    value  = Asn1OctetString.fromEncoded(octets).getOctets();
                  } catch (CodecException ex) {
                    // do nothing
                  }

                  if (value != null) {
                    receivedAuthorization = Base64.getUrlNoPaddingEncoder().encodeToString(value);
                  }
                }
              }
            }
          }
          break;
        }
        case AcmeConstants.DNS_01: {
          receivedAuthorization = validateDns(identifier, challId,
              chall.expectedAuthorization());
          break;
        }
        default: {
          throw new RuntimeException("unknown challenge type '" + type + "'");
        }
      }

      boolean authorizationValid = false;
      if (receivedAuthorization != null) {
        authorizationValid = chall.expectedAuthorization().equals(receivedAuthorization.trim());
      }

      if (authorizationValid) {
        LOG.info("validated challenge {}/{} for identifier {}/{}",
            chall.type(), challId, identifier.type(), identifier.value());
        chall.setValidated(Instant.now().truncatedTo(ChronoUnit.SECONDS));
        chall.setStatus(ChallengeStatus.valid);
      } else {
        LOG.warn("validation failed for challenge {}/{} for identifier {}/{} " +
                "(receivedPresent={}, expectedPresent={})",
            chall.type(), challId, identifier.type(), identifier.value(),
            receivedAuthorization != null, chall.expectedAuthorization() != null);
        chall.setStatus(ChallengeStatus.invalid);
      }

      if (chall.authz() != null && chall.authz().order() != null) {
        repo.flushOrderIfNotCached(chall.authz().order());
      }
    }

  }

  /**
   * Reloads the DNSSEC trust anchors if the file has been changed, at most once per
   * minute. If the new file is invalid, the current trust anchors are kept.
   */
  private void reloadTrustAnchorsIfChanged() {
    if (trustAnchorsFile == null) {
      return;
    }

    long now = System.currentTimeMillis();
    if (now < nextTrustAnchorsCheck) {
      return;
    }
    nextTrustAnchorsCheck = now + TRUST_ANCHORS_CHECK_INTERVAL_MS;

    try {
      List<DnsRecord> anchors = trustAnchorsFile.loadIfChanged();
      if (anchors != null) {
        dnssecValidator.setTrustAnchors(anchors);
        LOG.info("reloaded {} DNSSEC trust anchors from {}", anchors.size(),
            trustAnchorsFile.path());
      }
    } catch (IOException | IllegalArgumentException ex) {
      LogUtil.error(LOG, ex, "could not reload DNSSEC trust anchors from "
          + trustAnchorsFile.path() + ", keep the current ones");
    }
  }

  /**
   * Returns the expected authorization if one of the TXT records matches it exactly,
   * otherwise {@code null}.
   */
  private String validateDns(AcmeIdentifier identifier, ChallId challId,
                             String expectedAuthorization) {
    String host = identifier.value();
    if (host.startsWith("*.")) {
      host = host.substring(2);
    }

    LOG.debug("dns-01: host='{}'", identifier.value());

    String acmeDomain = "_acme-challenge." + host;
    try {
      List<String> txtValues = dnsClient.queryTxt(acmeDomain);
      if (txtValues.contains(expectedAuthorization)) {
        return expectedAuthorization;
      }

      LOG.debug("dns-01: none of the {} TXT records of '{}' matches", txtValues.size(), acmeDomain);
    } catch (IOException | IllegalArgumentException ex) {
      String message =  "error while validating challenge " + challId +
                        " for identifier " + identifier;
      LogUtil.error(LOG, ex, message);
    }

    return null;
  }

  /**
   * Resolves the challenge host with the configured DNS resolvers (A and AAAA records).
   * The caller must connect to the returned addresses instead of resolving the host
   * again, to prevent DNS rebinding.
   */
  private InetAddress[] resolveChallengeHost(String host) throws IOException {
    InetAddress[] addresses;
    if (host.indexOf(':') != -1 || host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
      // IP literal, e.g. in the location of a redirect: no DNS lookup
      addresses = new InetAddress[]{InetAddress.getByName(host)};
    } else {
      List<InetAddress> list;
      try {
        list = addressClient.queryAddresses(host);
      } catch (IllegalArgumentException ex) {
        throw new UnknownHostException("invalid host name " + host);
      }

      if (list.isEmpty()) {
        throw new UnknownHostException("found no address of host " + host);
      }
      addresses = list.toArray(new InetAddress[0]);
    }

    if (allowPrivateChallengeTargets) {
      return addresses;
    }

    for (InetAddress address : addresses) {
      if (isForbiddenAddress(address)) {
        throw new UnknownHostException("host resolves to forbidden address " +
            address.getHostAddress());
      }
    }
    return addresses;
  }

  private static boolean isForbiddenAddress(InetAddress address) {
    if (address.isAnyLocalAddress() || address.isLoopbackAddress()
        || address.isLinkLocalAddress() || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }

    byte[] bytes = address.getAddress();
    if (address instanceof Inet4Address) {
      int b0 = bytes[0] & 0xFF;
      int b1 = bytes[1] & 0xFF;
      if (b0 == 0 || b0 == 127) {
        return true;
      }

      if (b0 == 169 && b1 == 254) {
        return true;
      }

      if (b0 == 100 && b1 >= 64 && b1 <= 127) {
        return true;
      }

      return b0 >= 224;
    }

    if (address instanceof Inet6Address) {
      int b0 = bytes[0] & 0xFF;
      int b1 = bytes[1] & 0xFF;
      if ((b0 & 0xFE) == 0xFC) {
        return true;
      }

      return b0 == 0xFE && (b1 & 0xC0) == 0x80;
    }

    return false;
  }

  public void close() {
    stopMe = true;
  }

}
