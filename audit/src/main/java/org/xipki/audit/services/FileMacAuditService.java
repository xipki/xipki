// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolver;
import org.xipki.util.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.StringTokenizer;

/**
 * File-based MAC protected audit service.
 *
 * @author Lijun Liao (xipki)
 * @since 6.0.0
 */

public class FileMacAuditService extends MacAuditService {

  private static final Logger LOG = LoggerFactory.getLogger(FileMacAuditService.class);

  public static final String KEY_FILE = "file";

  private File logDir;

  private String logFileNamePrefix;

  private String logFileNameSuffix;

  private Instant lastMsOfToday;

  private OutputStreamWriter writer;

  private Path integrityFilePath;

  public FileMacAuditService() {
  }

  /*
    If there is no previous log line, the previous id is 0, and previous tag is empty.
   */
  @Override
  protected void storeLog(Instant date, long thisId, int eventType, String levelText,
                          long previousId, String message, String thisTag) {
    String logLine = formatDate(date) + DELIM + levelText + DELIM + eventType + DELIM + shardId +
        DELIM + thisId + DELIM + previousId + DELIM + thisTag + DELIM + message;

    try {
      if (date.isAfter(lastMsOfToday)) {
        ZonedDateTime now = ZonedDateTime.ofInstant(date, ZoneId.systemDefault());
        int yyyyMMddNow = DateUtil.getYyyyMMdd(now);
        lastMsOfToday = DateUtil.getLastMsOfDay(now);
        writer.close();
        writer = buildWriter(yyyyMMddNow);
      }

      writer.write(logLine);
      writer.write('\n');
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
    }
  }

  @Override
  protected void storeIntegrity(String integrityText) {
    if (integrityText != null) {
      try {
        writer.flush();
        Files.copy(new ByteArrayInputStream(integrityText.getBytes(StandardCharsets.UTF_8)),
                integrityFilePath, StandardCopyOption.REPLACE_EXISTING);
      } catch (IOException ex) {
        throw new IllegalStateException(ex);
      }
    }
  }

  @Override
  protected void doExtraInit(ConfPairs confPairs, PasswordResolver passwordResolver) {
    String str = confPairs.value(KEY_FILE);
    if (StringUtil.isBlank(str)) {
      throw new IllegalArgumentException("property " + KEY_FILE + " not defined");
    }

    File logFile = new File(str).getAbsoluteFile();
    this.logDir = logFile.getParentFile();
    this.logDir.mkdirs();

    String fileName = logFile.getName();
    int idx = fileName.lastIndexOf('.');
    logFileNameSuffix = idx == -1 ? "" : fileName.substring(idx);

    String prefix = idx == -1 ? fileName : fileName.substring(0, idx);

    if (shardId != 0) {
      prefix += "-" + shardId;
    }
    this.logFileNamePrefix = prefix + "_";

    // analyze the existing log files
    ZonedDateTime now = ZonedDateTime.now();

    int yyyyMMddNow = DateUtil.getYyyyMMdd(now);
    this.lastMsOfToday = DateUtil.getLastMsOfDay(now);

    File[] existingLogFiles = logDir.listFiles();
    int latestYyyyMMdd = 0;
    if (existingLogFiles != null) {
      for (File f : existingLogFiles) {
        String fName = f.getName();
        if (!(f.isFile() && fName.startsWith(logFileNamePrefix) && fName.endsWith(logFileNameSuffix)
              && fName.length() == logFileNamePrefix.length() + 10 + logFileNameSuffix.length())) {
          continue;
        }

        int startOffset = logFileNamePrefix.length();
        String ds = f.getName().substring(startOffset, startOffset + 10);
        try {
          int yyyyMMdd = Integer.parseInt(ds.substring(0, 4) + ds.substring(5, 7) + ds.substring(8, 10));
          if (yyyyMMdd > latestYyyyMMdd) {
            latestYyyyMMdd = yyyyMMdd;
          }
        } catch (Exception ex) {
          LOG.warn("could not parse name of file {}, ignore it",  f.getAbsolutePath());
        }

        if (latestYyyyMMdd > yyyyMMddNow) {
          throw new IllegalStateException("audit file " + f.getAbsolutePath()
                  + " is generated after " + yyyyMMddNow + ", this is not allowed.");
        }
      }
    }

    this.integrityFilePath = new File(logDir,
            this.logFileNamePrefix.substring(0, this.logFileNamePrefix.length() - 1) + ".integrity").toPath();

    File integrityFile = integrityFilePath.toFile();
    String integrityText;
    try {
      integrityText = integrityFile.exists() ? IoUtil.readLastNonBlankLine(integrityFile) : null;
    } catch (IOException ex) {
      throw new IllegalStateException("error reading " + integrityFile.getPath(), ex);
    }

    if (latestYyyyMMdd > 0) {
      String lastLine;
      File latestFile = new File(logDir, buildFilename(latestYyyyMMdd));
      try {
        lastLine = IoUtil.readLastNonBlankLine(latestFile);
      } catch (IOException e) {
        throw new IllegalStateException("error while reading " + latestFile.getPath());
      }

      StringTokenizer tokenizer = new StringTokenizer(lastLine, DELIM);
      int count = tokenizer.countTokens();
      String[] tokens = new String[count];
      for (int i = 0; i < count; i++) {
        tokens[i] = tokenizer.nextToken();
      }

      int previousId = Integer.parseInt(tokens[4]);
      if (previousId < 1) {
        throw new IllegalStateException("invalid previous id " + tokens[5]);
      }

      id.set(previousId);
      previousTag = tokens[6];
    }

    verify(id.get(), previousTag, integrityText, confPairs);
    this.writer = buildWriter(yyyyMMddNow);
  }

  private OutputStreamWriter buildWriter(int yyyyMMdd) {
    File currentLogFile = new File(logDir, buildFilename(yyyyMMdd));
    OutputStream fw;
    try {
      fw = new FileOutputStream(currentLogFile, true);
    } catch (IOException ex) {
      throw new IllegalStateException("error opening file " + currentLogFile.getPath());
    }

    return new OutputStreamWriter(fw);
  }

  private String buildFilename(int yyyyMMdd) {
    int year = yyyyMMdd / 10000;
    int month = yyyyMMdd % 10000 / 100;
    int day = yyyyMMdd % 100;
    String dateStr = year + "." + (month < 10 ? "0" + month : month) + "." + (day < 10 ? "0" + day : day);
    return logFileNamePrefix + dateStr + logFileNameSuffix;
  }

  @Override
  public void doClose() throws Exception {
    if (writer != null) {
      writer.flush();
      writer.close();
    }
  }

}
