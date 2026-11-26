// License Apache License 2.0

package org.xipki.mgmt.web.core;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.xipki.mgmt.web.audit.AuditTargetCapture;

/**
 * Small explicit route table; no reflection or annotation scanning.
 *
 * @author palos
 */
public final class Routes {
  @FunctionalInterface
  public interface Handler {
    Object handle(Request request) throws Exception;
  }

  private record Route(String method, String pattern, Handler handler, List<String> names) {}

  private final List<Route> routes = new ArrayList<>();
  private final AuditTargetCapture capture;

  public Routes() {
    this(null);
  }

  public Routes(AuditTargetCapture capture) {
    this.capture = capture;
  }

  public void add(String method, String pattern, Handler handler) {
    if (!method.matches("[A-Z]+") || !pattern.startsWith("/") || handler == null) {
      throw new IllegalArgumentException("Invalid route");
    }
    List<String> names = new ArrayList<>();
    for (String part : pattern.split("/")) {
      if (part.startsWith("{") && part.endsWith("}")) {
        names.add(part.substring(1, part.length() - 1));
      }
    }
    if (names.stream().distinct().count() != names.size()) {
      throw new IllegalArgumentException("Duplicate path parameter");
    }
    for (Route existing : routes) {
      if (existing.method().equals(method) && existing.pattern().equals(pattern)) {
        throw new IllegalArgumentException("Duplicate route: " + method + " " + pattern);
      }
    }
    routes.add(new Route(method, pattern, handler, List.copyOf(names)));
  }

  public Object dispatch(HttpServletRequest request, HttpServletResponse response)
      throws Exception {
    String path = request.getRequestURI().substring(request.getContextPath().length());
    List<Candidate> candidates = new ArrayList<>();
    for (Route route : routes) {
      if (!route.method().equalsIgnoreCase(request.getMethod())) {
        continue;
      }
      Map<String, String> values = match(route.pattern(), path);
      if (values != null) {
        candidates.add(new Candidate(route, values));
      }
    }
    if (candidates.isEmpty()) {
      throw new ApiException(404, "Not found");
    }
    candidates.sort(
        Comparator.comparingInt((Candidate candidate) -> specificity(candidate.route().pattern()))
            .reversed());
    if (candidates.size() > 1
        && specificity(candidates.get(0).route().pattern())
            == specificity(candidates.get(1).route().pattern())) {
      throw new ApiException(500, "Ambiguous route");
    }
    Candidate candidate = candidates.get(0);
    if (capture != null) {
      capture.captureParameters(request);
    }
    return candidate
        .route()
        .handler()
        .handle(new Request(request, response, candidate.values(), capture));
  }

  public List<String> patterns() {
    return routes.stream().map(Route::pattern).toList();
  }

  public record Endpoint(String method, String path) {}

  public List<Endpoint> entries() {
    return routes.stream().map(route -> new Endpoint(route.method(), route.pattern())).toList();
  }

  private static int specificity(String pattern) {
    int score = 0;
    for (String part : pattern.split("/")) {
      score += part.startsWith("{") ? 0 : 2;
    }
    return score * 100 + pattern.length();
  }

  private static Map<String, String> match(String pattern, String path) {
    String[] expected = parts(pattern), actual = parts(path);
    if (expected.length != actual.length) {
      return null;
    }
    Map<String, String> values = new LinkedHashMap<>();
    for (int i = 0; i < expected.length; i++) {
      String e = expected[i];
      String a = actual[i];
      if (e.startsWith("{") && e.endsWith("}")) {
        values.put(e.substring(1, e.length() - 1), decode(a));
      } else if (!e.equals(a)) {
        return null;
      }
    }
    return values;
  }

  private static String[] parts(String path) {
    return path.equals("/")
        ? new String[0]
        : Arrays.stream(path.split("/", -1)).filter(part -> !part.isEmpty()).toArray(String[]::new);
  }

  private static String decode(String value) {
    try {
      return URLDecoder.decode(value, StandardCharsets.UTF_8);
    } catch (Exception ex) {
      throw new ApiException(400, "Invalid path");
    }
  }

  private record Candidate(Route route, Map<String, String> values) {}

  public static final class Request {
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final Map<String, String> paths;
    private final AuditTargetCapture capture;
    private byte[] body;

    Request(
        HttpServletRequest request,
        HttpServletResponse response,
        Map<String, String> paths,
        AuditTargetCapture capture) {
      this.request = request;
      this.response = response;
      this.paths = paths;
      this.capture = capture;
    }

    public HttpServletRequest req() {
      return request;
    }

    public HttpServletResponse resp() {
      return response;
    }

    public String path(String name) {
      String value = paths.get(name);
      if (value == null) {
        throw new ApiException(400, "Invalid path");
      }
      return value;
    }

    public String param(String name) {
      String value = request.getParameter(name);
      if (Set.of("ca", "profile").contains(name)) {
        AuditTargetCapture.identify(request, name, value);
      }
      return value;
    }

    public String param(String name, String fallback) {
      String value = param(name);
      return value == null ? fallback : value;
    }

    public String required(String name) {
      String value = param(name);
      if (value == null || value.isBlank()) {
        throw new ApiException(400, "Missing request parameter");
      }
      return value;
    }

    public int integer(String name, int fallback) {
      String value = param(name);
      if (value == null || value.isBlank()) {
        return fallback;
      }
      try {
        return Integer.parseInt(value);
      } catch (NumberFormatException ex) {
        throw new ApiException(400, "Invalid request parameter");
      }
    }

    public boolean bool(String name, boolean fallback) {
      String value = param(name);
      if (value == null || value.isBlank()) {
        return fallback;
      }
      if ("true".equalsIgnoreCase(value)) {
        return true;
      }
      if ("false".equalsIgnoreCase(value)) {
        return false;
      }
      throw new ApiException(400, "Invalid request parameter");
    }

    public byte[] bodyBytes() throws IOException {
      if (request.getContentLengthLong() > 8 * 1024 * 1024) {
        throw new ApiException(413, "Request too large");
      }
      if (body == null) {
        body = request.getInputStream().readNBytes(8 * 1024 * 1024 + 1);
      }
      if (body.length > 8 * 1024 * 1024) {
        throw new ApiException(413, "Request too large");
      }
      return body;
    }

    public <T> T body(Class<T> type) {
      byte[] bytes;
      try {
        bytes = bodyBytes();
      } catch (IOException ex) {
        throw new ApiException(400, "Invalid request body");
      }
      if (bytes.length == 0) {
        throw new ApiException(400, "Request body is required");
      }
      String contentType = request.getContentType();
      if (contentType == null
          || !contentType
              .toLowerCase(Locale.ROOT)
              .matches("application/(?:[a-z0-9.-]+\\+)?json(?:;.*)?")) {
        throw new ApiException(415, "JSON content type required");
      }
      T value = Json.read(new String(bytes, StandardCharsets.UTF_8), type);
      if (value == null) {
        throw new IllegalArgumentException("Request body is required");
      }
      if (capture != null) {
        capture.captureBody(request, value);
      }
      return value;
    }

    public Upload upload(String name) {
      try {
        for (var part : request.getParts()) {
          if (name.equals(part.getName())) {
            return new PartUpload(part);
          }
        }
      } catch (IllegalStateException ex) {
        throw new ApiException(413, "Upload too large");
      } catch (Exception ex) {
        throw new ApiException(400, "Invalid upload");
      }
      throw new ApiException(400, "Uploaded file is required");
    }

    private record PartUpload(Part part) implements Upload {
      public byte[] getBytes() throws IOException {
        try (var stream = part.getInputStream()) {
          return stream.readAllBytes();
        }
      }

      public long getSize() {
        return part.getSize();
      }

      public boolean isEmpty() {
        return part.getSize() == 0;
      }

      public String getOriginalFilename() {
        String value = part.getSubmittedFileName();
        return value == null ? "" : value;
      }

      public String getContentType() {
        return part.getContentType();
      }

      public InputStream getInputStream() throws IOException {
        return part.getInputStream();
      }
    }
  }
}
