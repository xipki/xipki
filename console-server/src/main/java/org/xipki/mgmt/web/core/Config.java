// License Apache License 2.0

package org.xipki.mgmt.web.core;

import java.util.Map;

/**
 * Explicit settings: supplied map (tests), or JVM properties followed by environment.
 *
 * @author palos
 */
public final class Config {
  private final Map<String, String> values;

  public Config(Map<String, String> values) {
    this.values = Map.copyOf(values);
  }

  public Config() {
    this.values = null;
  }

  public static Config system() {
    return new Config();
  }

  public String getProperty(String key) {
    if (values != null) {
      return values.get(key);
    }
    String value = System.getProperty(key);
    return value == null ? System.getenv(key) : value;
  }

  public String getProperty(String key, String fallback) {
    String value = getProperty(key);
    return value == null ? fallback : value;
  }

  public <T> T getProperty(String key, Class<T> type, T fallback) {
    String value = getProperty(key);
    if (value == null) {
      return fallback;
    }
    Object parsed;
    if (type == String.class) {
      parsed = value;
    } else if (type == Integer.class) {
      parsed = Integer.valueOf(value);
    } else if (type == Long.class) {
      parsed = Long.valueOf(value);
    } else if (type == Boolean.class
        && (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false"))) {
      parsed = Boolean.valueOf(value);
    } else {
      throw new IllegalArgumentException("Unsupported setting: " + key);
    }
    return type.cast(parsed);
  }
}
