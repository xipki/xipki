// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.acme;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.ValidatingResolver;
import org.xipki.ca.gateway.acme.type.ChallengeStatus;
import org.xipki.security.OIDs;
import org.xipki.security.util.Asn1Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.http.HttpRespContent;
import org.xipki.util.extra.http.XiHttpClient;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * ACME component.
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

  private static final int MAX_DNS_CNAME_DEPTH = 8;

  private final AcmeRepo repo;

  private final Resolver dnsResolver;

  private final boolean dnssecValidation;

  private final boolean allowPrivateChallengeTargets;

  public ChallengeValidator(AcmeRepo repo, AcmeProtocolConf.Acme conf) throws InvalidConfException {
    this.repo = Args.notNull(repo, "repo");
    Args.notNull(conf, "conf");
    this.dnsResolver = buildDnsResolver(conf);
    this.dnssecValidation = conf.dnssecValidation();
    this.allowPrivateChallengeTargets = conf.allowPrivateChallengeTargets();
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

      AcmeChallenge chall = chall2.challenge();
      String type = chall.type();
      String receivedAuthorization = null;
      AcmeIdentifier identifier = chall2.identifier();
      // boolean authorizationValid = false;

      if (LOG.isDebugEnabled()) {
        String host = identifier.value();
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
          String host = identifier.value();
          // host = "localhost:9081";
          String url = "http://" + host + "/.well-known/acme-challenge/" + chall.token();
          try {
            ensureAllowedChallengeHost(host);
            XiHttpClient client = new XiHttpClient();
            HttpRespContent authzResp = client.httpGet(url);
            receivedAuthorization = new String(authzResp.content(), StandardCharsets.UTF_8);
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
            ensureAllowedChallengeHost(identifier.value());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{trustAll}, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(identifier.value(), 443)) {
              SSLParameters params = socket.getSSLParameters();
              params.setApplicationProtocols(new String[]{"acme-tls/1.0"});
              params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
              socket.setSSLParameters(params);

              SSLSession session = socket.getSession();
              certs = session.getPeerCertificates();
            }
          } catch (NoSuchAlgorithmException | IOException | KeyManagementException ex) {
            String message =  "error while validating challenge " + challId +
                              " for identifier " + identifier;
            LogUtil.error(LOG, ex, message);
          }

          boolean match = certs != null && certs.length > 0 && certs[0] instanceof X509Certificate;
          // check the SAN
          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            byte[] extnValue = cert.getExtensionValue(OIDs.Extn.subjectAlternativeName.getId());
            byte[] octets = Asn1Util.getOctetStringOctets(extnValue);
            GeneralNames generalNames = GeneralNames.getInstance(octets);
            GeneralName[] names = generalNames.getNames();
            match = (names != null && names.length == 1
                      && names[0].getTagNo() == GeneralName.dNSName);
            if (match) {
              String sanValue = Asn1Util.getIA5String(names[0].getName());
              match = identifier.value().equals(sanValue);
            }
          }

          if (match) {
            X509Certificate cert = (X509Certificate) certs[0];
            // check the critical extension id_pe_acmeIdentifier
            var criticalExtensionOids = cert.getCriticalExtensionOIDs();
            match = criticalExtensionOids != null
                && criticalExtensionOids.contains(OIDs.ACME.id_pe_acmeIdentifier.getId());
            if (match) {
              byte[] extnValue = cert.getExtensionValue(OIDs.ACME.id_pe_acmeIdentifier.getId());
              if (extnValue != null) {
                byte[] octets = Asn1Util.getOctetStringOctets(extnValue);
                if (octets != null) {
                  byte[] value  = Asn1Util.getOctetStringOctets(octets);
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
          receivedAuthorization = validateDns(identifier, challId);
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

  private static Resolver buildDnsResolver(AcmeProtocolConf.Acme conf) throws InvalidConfException {
    ExtendedResolver resolver;
    try {
      List<String> resolverNames = conf.dnsResolvers();
      if (resolverNames == null || resolverNames.isEmpty()) {
        resolver = new ExtendedResolver();
      } else {
        resolver = new ExtendedResolver(resolverNames.toArray(new String[0]));
      }
    } catch (IOException ex) {
      throw new InvalidConfException("could not initialize DNS resolver", ex);
    }

    if (!conf.dnssecValidation()) {
      return resolver;
    }

    ValidatingResolver validatingResolver = new ValidatingResolver(resolver);
    validatingResolver.setAddReasonToAdditional(true);
    String anchorFile = IoUtil.expandFilepath(conf.dnssecTrustAnchorsFile(), true);
    try (InputStream in = Files.newInputStream(Path.of(anchorFile))) {
      validatingResolver.loadTrustAnchors(in);
    } catch (IOException ex) {
      throw new InvalidConfException(
          "could not load DNSSEC trust anchors from " + conf.dnssecTrustAnchorsFile(), ex);
    }
    return validatingResolver;
  }

  private String validateDns(AcmeIdentifier identifier, ChallId challId) {
    String host = identifier.value();
    if (host.startsWith("*.")) {
      host = host.substring(2);
    }

    LOG.debug("dns-01: host='{}'", identifier.value());

    String acmeDomain = "_acme-challenge." + host;
    try {
      return queryDnsTxt(acmeDomain, challId, identifier, 0);
    } catch (IOException | ExecutionException ex) {
      String message =  "error while validating challenge " + challId +
                        " for identifier " + identifier;
      LogUtil.error(LOG, ex, message);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      String message =  "interrupted while validating challenge " + challId +
                        " for identifier " + identifier;
      LogUtil.error(LOG, ex, message);
    }

    return null;
  }

  private String queryDnsTxt(String acmeDomain, ChallId challId, AcmeIdentifier identifier, int depth)
      throws IOException, ExecutionException, InterruptedException {
    if (depth > MAX_DNS_CNAME_DEPTH) {
      LOG.warn("dns-01: too many CNAME redirects for '{}'", acmeDomain);
      return null;
    }

    Name queryName = Name.fromString(acmeDomain, Name.root);
    Record question = Record.newRecord(queryName, Type.TXT, DClass.IN);
    Message query = Message.newQuery(question);
    Message response = dnsResolver.sendAsync(query).toCompletableFuture().get();

    if (response.getRcode() != Rcode.NOERROR) {
      LOG.debug("dns-01: query '{}' returned rcode {}", queryName, Rcode.string(response.getRcode()));
      return null;
    }

    if (dnssecValidation && !response.getHeader().getFlag(Flags.AD)) {
      LOG.warn("dns-01 DNSSEC validation failed for '{}' ({})",
          queryName, getDnssecFailureReason(response));
      return null;
    }

    Name cnameTarget = null;
    for (Record record : response.getSection(Section.ANSWER)) {
      if (record.getType() == Type.TXT && queryName.equals(record.getName())) {
        TXTRecord txt = (TXTRecord) record;
        List<String> strings = txt.getStrings();
        if (strings != null && !strings.isEmpty()) {
          return strings.get(0);
        }
      } else if (record.getType() == Type.CNAME && queryName.equals(record.getName())) {
        cnameTarget = ((CNAMERecord) record).getTarget();
      }
    }

    if (cnameTarget != null) {
      LOG.debug("dns-01: following CNAME '{}' -> '{}'", queryName, cnameTarget);
      return queryDnsTxt(cnameTarget.toString(), challId, identifier, depth + 1);
    }

    return null;
  }

  private static String getDnssecFailureReason(Message response) {
    for (Record record : response.getSection(Section.ADDITIONAL)) {
      if (record.getType() == Type.TXT
          && record.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS
          && Name.root.equals(record.getName())) {
        List<String> strings = ((TXTRecord) record).getStrings();
        return (strings == null || strings.isEmpty()) ? "missing validation reason"
            : String.join("", strings);
      }
    }

    return "response not DNSSEC-authenticated";
  }

  private void ensureAllowedChallengeHost(String host) throws UnknownHostException {
    if (allowPrivateChallengeTargets) {
      return;
    }

    ensurePublicAddressableHost(host);
  }

  private static void ensurePublicAddressableHost(String host) throws UnknownHostException {
    InetAddress[] addresses = InetAddress.getAllByName(host);
    for (InetAddress address : addresses) {
      if (isForbiddenAddress(address)) {
        throw new UnknownHostException("host resolves to forbidden address " + address.getHostAddress());
      }
    }
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
