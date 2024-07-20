// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import org.slf4j.Logger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Set;

/**
 * LOG utility class.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class LogUtil {

  private static boolean systemInfoLogged = false;

  private LogUtil() {
  }

  public static void logSystemInfo(Logger log) {
    if (systemInfoLogged) {
      return;
    }

    String[] prefixes = {"java.", "jdk.", "os.", "user."};
    StringBuilder sb = new StringBuilder(1000);
    Properties props = System.getProperties();
    Set<String> propNames = props.stringPropertyNames();
    for (String prefix : prefixes) {
      for (String propName : propNames) {
        if (propName.startsWith(prefix)) {
          sb.append(propName).append(": ").append(props.getProperty(propName)).append("\n");
        }
      }
    }
    sb.deleteCharAt(sb.length() - 1);
    log.info(sb.toString());
    systemInfoLogged = true;
  }

  public static void error(Logger log, Throwable th) {
    if (!log.isErrorEnabled()) {
      return;
    }

    // this operation is expensive, hence don't abuse it.
    StackTraceElement[] traces = Thread.currentThread().getStackTrace();
    if (traces.length > 2) {
      StackTraceElement trace = traces[2];
      log.error("({}.{} {}), {}: {}", trace.getClassName(), trace.getMethodName(), trace.getLineNumber(),
          th.getClass().getName(), th.getMessage());
    } else {
      log.error("{}: {}", th.getClass().getName(), th.getMessage());
    }
    if (th instanceof RuntimeException) {
      log.error("Exception", th);
    } else {
      log.debug("Exception", th);
    }
  }

  public static void error(Logger log, Throwable th, String msg) {
    if (!log.isErrorEnabled()) {
      return;
    }

    // this operation is expensive, hence don't abuse it.
    StackTraceElement[] traces = Thread.currentThread().getStackTrace();
    if (traces.length > 2) {
      StackTraceElement trace = traces[2];
      log.error("({}.{} {}) {}, {}: {}", trace.getClassName(), trace.getMethodName(), trace.getLineNumber(), msg,
          th.getClass().getName(), th.getMessage());
    } else {
      log.error("{}, {}: {}", msg, th.getClass().getName(), th.getMessage());
    }

    if (th instanceof RuntimeException) {
      log.error(msg, th);
    } else {
      log.debug(msg, th);
    }
  }

  public static void warn(Logger log, Throwable th) {
    if (!log.isWarnEnabled()) {
      return;
    }

    // this operation is expensive, don't abuse it.
    StackTraceElement[] traces = Thread.currentThread().getStackTrace();
    if (traces.length > 2) {
      StackTraceElement trace = traces[2];
      log.error("({}.{} {}), {}: {}", trace.getClassName(), trace.getMethodName(), trace.getLineNumber(),
          th.getClass().getName(), th.getMessage());
    } else {
      log.warn("{}: {}", th.getClass().getName(), th.getMessage());
    }

    if (th instanceof RuntimeException) {
      log.warn("Exception", th);
    } else {
      log.debug("Exception", th);
    }
  }

  public static void warn(Logger log, Throwable th, String msg) {
    if (!log.isWarnEnabled()) {
      return;
    }

    // this operation is expensive, hence don't abuse it.
    StackTraceElement[] traces = Thread.currentThread().getStackTrace();
    if (traces.length > 2) {
      StackTraceElement trace = traces[2];
      log.warn("({}.{} {}) {}, {}: {}", trace.getClassName(), trace.getMethodName(), trace.getLineNumber(), msg,
          th.getClass().getName(), th.getMessage());
    } else {
      log.warn("{}, {}: {}", msg, th.getClass().getName(), th.getMessage());
    }
    if (th instanceof RuntimeException) {
      log.warn(msg, th);
    } else {
      log.debug(msg, th);
    }
  }

  /**
   * Formats certificate serial number.
   * @param serialNumber certificate serial number
   * @return formatted certificate serial number
   */
  public static String formatCsn(BigInteger serialNumber) {
    return "0x" + Hex.encode(serialNumber.toByteArray());
  }

  public static String base64Encode(byte[] bytes) {
    return (bytes == null) ? "NULL"
        : (bytes.length == 0) ? "EMPTY" : Base64.encodeToString(bytes, true);
  }

  private static String toUtf8String(byte[] bytes) {
    return (bytes == null) ? "NULL" : new String(bytes, StandardCharsets.UTF_8);
  }

  public static void logTextReqResp(
      String prefix, Logger log, boolean logReqResp, boolean viaPost,
      String requestURI, byte[] requestBytes, byte[] respBody) {
    if (logReqResp && log.isDebugEnabled()) {
      if (viaPost) {
        log.debug("{} HTTP POST path: {}\nRequest:\n{}\nResponse:\n{}",
            prefix, requestURI, toUtf8String(requestBytes), toUtf8String(respBody));
      } else {
        log.debug("{} HTTP GET path: {}\nResponse:\n{}", prefix, requestURI, toUtf8String(respBody));
      }
    }
  }

  public static void logReqResp(
      String prefix, Logger log, boolean logReqResp, boolean viaPost,
      String requestURI, byte[] requestBytes, byte[] respBody) {
    if (logReqResp && log.isDebugEnabled()) {
      if (viaPost) {
        log.debug("{} HTTP POST path: {}\nRequest:\n{}\nResponse:\n{}",
            prefix, requestURI, base64Encode(requestBytes), base64Encode(respBody));
      } else {
        log.debug("{} HTTP GET path: {}\nResponse:\n{}", prefix, requestURI, base64Encode(respBody));
      }
    }
  }

}
