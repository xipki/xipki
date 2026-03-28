// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CertListInfo;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.util.codec.Base64;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.util.datasource.DatabaseType;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.DateUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * The CA management shell.
 *
 * @author Lijun Liao (xipki)
 */
class CaMgmtUtil {
  abstract static class CaMgmtCommand extends ShellBaseCommand {

    protected CaMgmtClient client() throws Exception {
      return CaMgmtRuntime.get();
    }
  }

  static String formatNames(String what, Set<String> names) {
    int size = names.size();
    StringBuilder sb = new StringBuilder();
    if (size == 0 || size == 1) {
      sb.append(size == 0 ? "no" : "1").append(' ').append(what).append(" is configured\n");
    } else {
      sb.append(size).append(' ').append(what).append("s are configured:\n");
    }

    List<String> sorted = new ArrayList<>(names);
    Collections.sort(sorted);
    for (String name : sorted) {
      sb.append('\t').append(name).append('\n');
    }
    return sb.toString();
  }

  static String loadOptionalText(String conf, String confFile) throws Exception {
    if (conf == null && confFile != null) {
      return StringUtil.toUtf8String(IoUtil.read(confFile));
    }
    return conf;
  }

  static void appendLabeledCaNames(
      StringBuilder sb, String label, Set<String> caNames, CaMgmtClient client)
      throws Exception {
    sb.append(label).append(":\n");
    if (CollectionUtil.isEmpty(caNames)) {
      sb.append("  -\n");
      return;
    }

    List<String> sorted = new ArrayList<>(caNames);
    Collections.sort(sorted);
    for (String caName : sorted) {
      Set<String> aliases = client.getAliasesForCa(caName);
      sb.append("  ").append(caName);
      if (CollectionUtil.isNotEmpty(aliases)) {
        sb.append(" (aliases ").append(aliases).append(')');
      }
      sb.append('\n');
    }
  }

  static Instant parseDate(String dateStr) {
    return StringUtil.isBlank(dateStr) ? null
        : DateUtil.parseUtcTimeyyyyMMddhhmmss(dateStr);
  }

  static String formatCertListLine(int index, CertListInfo info) {
    return StringUtil.concat(
        StringUtil.formatAccount(index, 4), " | ",
        StringUtil.formatText(info.serialNumber().toString(16), 40), " | ",
        info.notBefore().toString(), " | ",
        info.notAfter().toString(), " | ", info.subject());
  }

  static String printDbInfo(ConfigurableProperties dbProps, int scriptFilePathLen) {
    String schema = dbProps.getProperty("liquibase.schema");
    if (schema != null) {
      schema = schema.trim();
      if (schema.isEmpty()) {
        schema = null;
      }
    }

    String user = dbProps.getProperty("dataSource.user");
    if (user == null) {
      user = dbProps.getProperty("username");
    }

    String url = dbProps.getProperty("jdbcUrl");
    if (url != null) {
      return printDbInfo(user, url, schema, scriptFilePathLen);
    }

    String datasourceClassName = dbProps.getProperty("dataSourceClassName");
    if (datasourceClassName == null) {
      throw new IllegalArgumentException("unsupported configuration");
    }

    StringBuilder urlBuilder = new StringBuilder();
    String lower = datasourceClassName.toLowerCase();
    if (lower.contains("org.h2.")) {
      String dataSourceUrl = dbProps.getProperty("dataSource.url");
      urlBuilder.append(dataSourceUrl);
      if (schema != null) {
        urlBuilder.append(";INIT=CREATE SCHEMA IF NOT EXISTS ").append(schema);
      }
    } else if (lower.contains("mysql.")) {
      urlBuilder.append("jdbc:mysql://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.port")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (lower.contains("mariadb.")) {
      String str = dbProps.getProperty("dataSource.url");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:mariadb://")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.port")).append("/")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (lower.contains("oracle.")) {
      String str = dbProps.getProperty("dataSource.URL");
      if (StringUtil.isNotBlank(str)) {
        urlBuilder.append(str);
      } else {
        urlBuilder.append("jdbc:oracle:thin:@")
            .append(dbProps.getProperty("dataSource.serverName")).append(":")
            .append(dbProps.getProperty("dataSource.portNumber")).append(":")
            .append(dbProps.getProperty("dataSource.databaseName"));
      }
    } else if (lower.contains("com.ibm.db2.")) {
      schema = dbProps.getProperty("dataSource.currentSchema");
      urlBuilder.append("jdbc:db2://")
          .append(dbProps.getProperty("dataSource.serverName")).append(":")
          .append(dbProps.getProperty("dataSource.portNumber")).append("/")
          .append(dbProps.getProperty("dataSource.databaseName"));
    } else if (lower.contains("postgresql.") || lower.contains("impossibl.postgres.")) {
      String serverName;
      String portNumber;
      String databaseName;
      if (lower.contains("postgresql.")) {
        serverName = dbProps.getProperty("dataSource.serverName");
        portNumber = dbProps.getProperty("dataSource.portNumber");
        databaseName = dbProps.getProperty("dataSource.databaseName");
      } else {
        serverName = dbProps.getProperty("dataSource.host");
        portNumber = dbProps.getProperty("dataSource.port");
        databaseName = dbProps.getProperty("dataSource.database");
      }

      urlBuilder.append("jdbc:postgresql://").append(serverName)
          .append(":").append(portNumber).append("/").append(databaseName);
    } else if (lower.contains("hsqldb.")) {
      urlBuilder.append(dbProps.getProperty("dataSource.url"));
    } else {
      throw new IllegalArgumentException("unsupported database type " + datasourceClassName);
    }

    return printDbInfo(user, urlBuilder.toString(), schema, scriptFilePathLen);
  }

  private static String printDbInfo(
      String username, String url, String schema, int scriptFilePathLen) {
    String boundary = "-".repeat(2 + Math.max(
        "Start executing script ".length() + scriptFilePathLen,
        "script file: ".length() + url.length()));
    String msg = boundary + "\n       user: " + username + "\n        URL: " + url;
    if (schema != null) {
      msg += "\n     schema: " + schema;
    }
    System.out.println(msg);
    return boundary;
  }

  static String dbTypeName(DatabaseType dbType) {
    switch (dbType) {
      case H2:
        return "h2";
      case POSTGRES:
        return "postgresql";
      case DB2:
        return "db2";
      case ORACLE:
        return "oracle";
      case MYSQL:
      case MARIADB:
        return "mysql";
      case HSQL:
        return "hsqldb";
      default:
        throw new IllegalArgumentException("unknown database type " + dbType);
    }
  }

  static Path resolveSqlScript(String scriptFile, String type) {
    Path p = Paths.get(scriptFile);
    if (Files.exists(p)) {
      return p;
    }

    String fileName = p.getFileName().toString();
    int idx = fileName.lastIndexOf('.');
    fileName = fileName.substring(0, idx) + "." + type + fileName.substring(idx);
    Path parentP = p.getParent();
    Path candidate = parentP == null ? Paths.get(fileName)
        : Paths.get(parentP.toString(), fileName);

    if (Files.exists(candidate)) {
      return candidate;
    }

    candidate = parentP == null ? Paths.get(type, fileName)
        : Paths.get(parentP.toString(), type, fileName);
    if (Files.exists(candidate)) {
      return candidate;
    }

    throw new IllegalArgumentException("Could not find script file " + scriptFile);
  }

  static String canonicalizeSignerConf(String keystoreType, String signerConf)
      throws Exception {
    if (StringUtil.isBlank(keystoreType) || StringUtil.isBlank(signerConf)) {
      return signerConf;
    }

    if (!signerConf.contains("file:") && !signerConf.contains("base64:")
        && !signerConf.contains("FILE:") && !signerConf.contains("BASE64:")) {
      return signerConf;
    }

    ConfPairs pairs = new ConfPairs(signerConf);
    String keystoreConf = pairs.value("keystore");
    if (keystoreConf == null || pairs.value("password") == null) {
      return signerConf;
    }

    byte[] keystoreBytes;
    if (StringUtil.startsWithIgnoreCase(keystoreConf, "file:")) {
      keystoreBytes = IoUtil.read(keystoreConf.substring("file:".length()));
    } else if (StringUtil.startsWithIgnoreCase(keystoreConf, "base64:")) {
      keystoreBytes = Base64.decode(keystoreConf.substring("base64:".length()));
    } else {
      return signerConf;
    }

    pairs.putPair("keystore", "base64:" + Base64.encodeToString(keystoreBytes));
    return pairs.getEncoded();
  }

  static boolean parseEnabled(String value, boolean defaultValue, String optionName) {
    if (StringUtil.isBlank(value)) {
      return defaultValue;
    }

    if (StringUtil.orEqualsIgnoreCase(value, "yes", "true")) {
      return true;
    } else if (StringUtil.orEqualsIgnoreCase(value, "no", "false")) {
      return false;
    } else {
      throw new IllegalArgumentException("invalid " + optionName + " value " + value);
    }
  }

  static List<String> getUris(List<String> uris) {
    if (uris == null) {
      return null;
    }

    for (String uri : uris) {
      if (CaManager.NULL.equalsIgnoreCase(uri)) {
        return Collections.emptyList();
      }
    }
    return new ArrayList<>(uris);
  }
}
