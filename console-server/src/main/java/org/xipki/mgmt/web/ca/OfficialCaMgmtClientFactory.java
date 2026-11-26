// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Path;
import java.util.Set;
import org.xipki.util.http.SslContextConfWrapper;

/** Creates the XiPKI-provided management client with Console transport security policy. */
public final class OfficialCaMgmtClientFactory {
  private static final String CONNECT_TIMEOUT = "sun.net.client.defaultConnectTimeout";
  private static final String READ_TIMEOUT = "sun.net.client.defaultReadTimeout";
  private static final String RETRY_POST = "sun.net.http.retryPost";

  /**
   * Creates and initializes an official XiPKI CA management client using the dedicated management
   * identity. Redirects are disabled process-wide because the official client does not expose its
   * connection object, and following a redirect could replay a mutation or disclose the client
   * identity to another endpoint. The Console is a standalone process, so this is also the desired
   * policy for its other server-side HTTP clients.
   */
  public static org.xipki.ca.mgmt.client.CaMgmtClient create(
      String address, Path keyStore, char[] password, Path trustAnchors) throws Exception {
    URI uri = URI.create(address.endsWith("/") ? address : address + "/");
    if (!"https".equalsIgnoreCase(uri.getScheme())
        || uri.getHost() == null
        || uri.getRawUserInfo() != null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      throw new IllegalArgumentException("Invalid HTTPS management URL");
    }
    if (password == null || password.length == 0) {
      throw new IllegalArgumentException("Management keystore password is required");
    }

    // CaMgmtClient does not set per-connection transport policy, so establish bounded process
    // defaults before its first URLConnection is opened. Explicit operator values are retained.
    boundedDefault(CONNECT_TIMEOUT, 15_000);
    boundedDefault(READ_TIMEOUT, 60_000);
    // Management reads and writes are both POST requests. JDK automatic retry would make a
    // mutation outcome ambiguous after a connection failure, so operators cannot enable it.
    System.setProperty(RETRY_POST, "false");
    HttpURLConnection.setFollowRedirects(false);

    var ssl = new SslContextConfWrapper();
    ssl.setUseSslConf(true);
    ssl.setSslStoreType("PKCS12");
    ssl.setSslKeystore(keyStore.toString());
    ssl.setSslKeystorePassword(new String(password));
    ssl.setSslTrustanchors(Set.of(trustAnchors.toString()));
    ssl.setSslHostnameVerifier("default");

    var client = new org.xipki.ca.mgmt.client.CaMgmtClient();
    client.init(ssl, uri.toString());
    client.initIfNotDone();
    return client;
  }

  /** Sets one positive millisecond timeout while preserving an explicit operator value. */
  private static void boundedDefault(String name, int fallback) {
    String value = System.getProperty(name);
    if (value == null) {
      System.setProperty(name, Integer.toString(fallback));
      return;
    }
    try {
      if (Integer.parseInt(value) <= 0) {
        throw new IllegalArgumentException(name + " must be positive");
      }
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException(name + " must be a positive integer", ex);
    }
  }

  private OfficialCaMgmtClientFactory() {}
}
