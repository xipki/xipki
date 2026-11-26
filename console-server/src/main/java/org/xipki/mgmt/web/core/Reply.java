// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A controller result; HTTP writing is centralized in the servlet.
 *
 * @author palos
 */
public record Reply<T>(int status, Map<String, String> headers, T body) {
  public Reply {
    headers = Map.copyOf(headers);
  }

  public static <T> Reply<T> ok(T body) {
    return new Reply<>(200, Map.of(), body);
  }

  public static Builder ok() {
    return status(200);
  }

  public static Builder status(int status) {
    return new Builder(status);
  }

  public static Builder badRequest() {
    return status(400);
  }

  public static Builder notFound() {
    return status(404);
  }

  public static Builder noContent() {
    return status(204);
  }

  public static final class Builder {
    private final int status;
    private final Map<String, String> headers = new LinkedHashMap<>();

    private Builder(int status) {
      this.status = status;
    }

    public Builder header(String name, String value) {
      headers.put(name, value);
      return this;
    }

    public Builder contentType(String type) {
      return header("Content-Type", type);
    }

    public Builder contentLength(long length) {
      return header("Content-Length", Long.toString(length));
    }

    public <T> Reply<T> body(T body) {
      return new Reply<>(status, headers, body);
    }

    public <T> Reply<T> build() {
      return body(null);
    }
  }
}
