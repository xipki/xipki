// License Apache License 2.0

package org.xipki.mgmt.web;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.xipki.mgmt.web.Main.LiteServlet;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.core.ApiException;
import org.xipki.mgmt.web.core.Config;

/**
 * @author palos
 */
class StartupContractTest {
  @TempDir Path directory;

  @Test
  void distinguishesCaRejectionFromUncertainTransportOutcome() {
    assertEquals(400, LiteServlet.error(new CaMgmtException("rejected"), null).status());
    assertEquals(
        503, LiteServlet.error(new CaMgmtException(new IOException("unavailable")), null).status());
  }

  @Test
  void exposesValidatedSubjectErrorsButHidesUnexpectedArguments() {
    var error =
        LiteServlet.error(
            new ApiException(400, "CSR subject order does not match the certificate profile"),
            null);
    assertEquals(400, error.status());
    assertEquals(
        Map.of("error", "CSR subject order does not match the certificate profile"), error.body());
    assertEquals(
        Map.of("error", "Invalid request fields or format"),
        LiteServlet.error(new IllegalArgumentException("secret"), null).body());
  }

  @Test
  void acceptsSingleTerminalNewlineAndRejectsAmbiguousSecrets() throws Exception {
    Path file = directory.resolve("password");
    Files.writeString(file, "test password\r\n");
    assertEquals(
        "test password", Main.secret(new Config(Map.of("file", file.toString())), "value", "file"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Main.secret(
                new Config(Map.of("file", file.toString(), "value", "x")), "value", "file"));
    Files.writeString(file, "one\ntwo\n");
    assertThrows(
        IllegalArgumentException.class,
        () -> Main.secret(new Config(Map.of("file", file.toString())), "value", "file"));
  }

  @Test
  void bundlesExistingFrontendAndEveryReferencedAsset() throws Exception {
    try (var index = Main.class.getResourceAsStream("/static/index.html")) {
      assertNotNull(index, "Build the existing frontend before packaging the lite backend");
      var matcher =
          Pattern.compile("(?:src|href)=\"(/assets/[^\"]+)\"")
              .matcher(new String(index.readAllBytes(), StandardCharsets.UTF_8));
      int count = 0;
      while (matcher.find()) {
        assertNotNull(Main.class.getResource("/static" + matcher.group(1)));
        count++;
      }
      assertTrue(count > 0);
    }
  }

  @Test
  void multipartParserHasExplicitPartAndHeaderBudgets() throws Exception {
    var tomcat = Main.server(0, directory, new LiteServlet(null, null, null));
    try {
      var connector = tomcat.getConnector();
      assertEquals("17", connector.getProperty("maxPartCount"));
      assertEquals("1024", connector.getProperty("maxPartHeaderSize"));
      assertEquals(256, connector.getProperty("maxConnections"));
    } finally {
      tomcat.destroy();
    }
  }
}
