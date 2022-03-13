/*
 *
 * Copyright (c) 2013 - 2022 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import java.util.Calendar;
import java.util.StringTokenizer;
import java.util.TimeZone;

/**
 * File-based MAC protected audit service.
 *
 * @author Lijun Liao
 * @since 5.4.0
 */

public class FileMacAuditService extends MacAuditService {

  private static Logger LOG = LoggerFactory.getLogger(FileMacAuditService.class);

  public static final String KEY_FILE = "file";

  private File logDir;

  private String logFileNamePrefix;

  private String logFileNameSuffix;

  private long lastMsOfToday;

  private OutputStreamWriter writer;

  private Path integrityFilePath;

  public FileMacAuditService() {
  }

  /*
    If there is no previous log line, the previous id is 0, and previous tag is empty.
   */
  @Override
  protected void storeLog(
          Instant date, long thisId, int eventType, String levelText,
          long previousId, String message, String thisTag) {
    StringBuilder sb = new StringBuilder(message.length());
    sb.append(formatDate(date))
            .append(DELIM).append(levelText)
            .append(DELIM).append(eventType)
            .append(DELIM).append(shardId)
            .append(DELIM).append(thisId)
            .append(DELIM).append(previousId)
            .append(DELIM).append(thisTag)
            .append(DELIM).append(message);

    String logLine = sb.toString();

    long ms = date.toEpochMilli();
    try {
      if (ms > lastMsOfToday) {
        Calendar now = Calendar.getInstance(TimeZone.getDefault());
        now.setTimeInMillis(ms);
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
    Calendar now = Calendar.getInstance(TimeZone.getDefault());

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
        String dateStr = f.getName().substring(startOffset, startOffset + 10);
        try {
          int yyyyMMdd = Integer.parseInt(
                  dateStr.substring(0, 4) + dateStr.substring(5, 7) + dateStr.substring(8, 10));
          if (yyyyMMdd > latestYyyyMMdd) {
            latestYyyyMMdd = yyyyMMdd;
          }
        } catch (Exception ex) {
          System.err.println("could not parse name of file " + f.getAbsolutePath() + ", ignore it");
        }

        if (latestYyyyMMdd > yyyyMMddNow) {
          throw new IllegalStateException("audit file " + f.getAbsolutePath()
                  + " is generated after " + yyyyMMddNow + ", this is not allowed.");
        }
      }
    }

    this.integrityFilePath = new File(logDir,
            this.logFileNamePrefix.substring(0, this.logFileNamePrefix.length() - 1)
                    + ".integrity").toPath();

    File integrityFile = integrityFilePath.toFile();
    String integrityText;
    try {
      integrityText = integrityFile.exists()
              ? IoUtil.readLastNonBlankLine(integrityFile) : null;
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
    String dateStr = year + "." + (month < 10 ? "0" + month : month)
                      + "." + (day < 10 ? "0" + day : day);
    return logFileNamePrefix + dateStr + logFileNameSuffix;
  }

  @Override
  public void doClose() throws Exception {
    writer.flush();
    writer.close();
  }

}
