// License Apache License 2.0

package org.xipki.mgmt.web.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * @author palos
 */
class AuditFilterTest {
  private static final List<String> DOWNLOADS =
      List.of(
          "/api/audit/export",
          "/api/system/export",
          "/api/ca/example/certificates",
          "/api/ca-enrollments/example/csr",
          "/api/cert/example/123/download",
          "/api/crl/example/current",
          "/api/crl/example/123");

  @Test
  void skipsReadRequestsExceptExplicitGetDownloadsAndExports() {
    List<AuditEvent> events = new ArrayList<>();
    AuditFilter filter =
        new AuditFilter(
            new AuditService(null) {
              @Override
              public void record(AuditEvent event) {
                events.add(event);
              }
            });

    for (String method : List.of("GET", "HEAD", "FETCH", "OPTIONS")) {
      complete(filter, request(method, "/api/ca"));
      complete(filter, request(method, "/api/audit"));
      complete(filter, request(method, "/api/auth/me"));
      complete(filter, request(method, "/api/cert/example/123"));
      complete(filter, request(method, "/api/other/download"));
    }
    assertEquals(0, events.size());

    for (String path : DOWNLOADS) {
      complete(filter, request("GET", path));
    }
    assertEquals(DOWNLOADS, events.stream().map(AuditEvent::requestPath).toList());
    assertEquals(
        List.of("SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS"),
        events.stream().map(AuditEvent::result).toList());

    complete(filter, request("HEAD", "/api/audit/export"));
    complete(filter, request("FETCH", "/api/system/export"));
    assertEquals(DOWNLOADS.size(), events.size());

    complete(filter, request("POST", "/api/ca"));
    assertEquals(
        List.of("ATTEMPT", "SUCCESS"),
        events.subList(DOWNLOADS.size(), events.size()).stream().map(AuditEvent::result).toList());
  }

  private static void complete(AuditFilter filter, HttpServletRequest request) {
    long start = filter.begin(request);
    filter.finish(request, 200, null, null, start);
  }

  private static HttpServletRequest request(String method, String path) {
    Map<String, Object> attributes = new HashMap<>();
    return (HttpServletRequest)
        Proxy.newProxyInstance(
            HttpServletRequest.class.getClassLoader(),
            new Class<?>[] {HttpServletRequest.class},
            (proxy, call, args) ->
                switch (call.getName()) {
                  case "getMethod" -> method;
                  case "getRequestURI" -> path;
                  case "getRemoteAddr" -> "127.0.0.1";
                  case "getAttribute" -> attributes.get(args[0]);
                  case "setAttribute" -> {
                    attributes.put((String) args[0], args[1]);
                    yield null;
                  }
                  default -> null;
                });
  }
}
