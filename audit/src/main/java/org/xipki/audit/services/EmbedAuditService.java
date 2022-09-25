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
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.password.PasswordResolver;
import org.xipki.password.PasswordResolverException;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The embedded audit service.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EmbedAuditService implements AuditService {

  public static final String KEY_FILE = "file";

  public static final String KEY_SIZE = "size";

  private static final String DELIM = " | ";

  private static Logger LOG = LoggerFactory.getLogger(EmbedAuditService.class);

  private static final DateTimeFormatter DTF = DateTimeFormatter.ofPattern("yyyy.MM.dd-HH:mm:ss.SSS");

  private final ZoneId timeZone = ZoneId.systemDefault();

  private File logDir;

  private String logFileNamePrefix;

  private String logFileNameSuffix;

  private long lastMsOfToday;

  private int maxFileSize;

  private OutputStreamWriter writer;

  private Path writerPath;

  private String writerFileCoreName;

  public EmbedAuditService() {
  }

  @Override
  public void init(String conf) {
    try {
      init(conf, null);
    } catch (PasswordResolverException | InvalidConfException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Override
  public void init(String conf, PasswordResolver passwordResolver)
      throws PasswordResolverException, InvalidConfException {
    ConfPairs confPairs = new ConfPairs(conf);
    String str = confPairs.value(KEY_SIZE);

    final int mb = 1024 * 1024;

    if (str == null) {
      this.maxFileSize = 10 * mb; // 10 MB
    } else {
      str = str.trim().toLowerCase(Locale.ROOT);
      if (str.endsWith("gb")) {
        this.maxFileSize = Integer.parseInt(str.substring(0, str.length() - 2).trim()) * 1024 * mb;
      } else if (str.endsWith("mb")) {
        this.maxFileSize = Integer.parseInt(str.substring(0, str.length() - 2).trim()) * mb;
      } else if (str.endsWith("kb")) {
        this.maxFileSize = Integer.parseInt(str.substring(0, str.length() - 2).trim()) * 1024;
      } else {
        this.maxFileSize = Integer.parseInt(str);
      }

      if (this.maxFileSize < mb) {
        throw new InvalidConfException("invalid size " + str);
      }
    }

    String logFilePath = confPairs.value(KEY_FILE);

    if (StringUtil.isBlank(logFilePath)) {
      logFilePath = "logs/audit.log";
    }

    File logFile = new File(logFilePath).getAbsoluteFile();
    this.logDir = logFile.getParentFile();
    this.logDir.mkdirs();

    String fileName = logFile.getName();
    int idx = fileName.lastIndexOf('.');
    logFileNameSuffix = idx == -1 ? "" : fileName.substring(idx);

    String prefix = idx == -1 ? fileName : fileName.substring(0, idx);
    this.logFileNamePrefix = prefix + "_";

    // analyze the existing log files
    Calendar now = Calendar.getInstance(TimeZone.getDefault());

    int yyyyMMddNow = DateUtil.getYyyyMMdd(now);
    this.lastMsOfToday = DateUtil.getLastMsOfDay(now);

    this.writer = buildWriter(yyyyMMddNow);
  }

  @Override
  public void logEvent(AuditEvent event) {
    storeLog(AuditService.AUDIT_EVENT, event.getLevel(), event.toTextMessage());
  } // method logEvent

  @Override
  public void logEvent(PciAuditEvent event) {
    storeLog(AuditService.PCI_AUDIT_EVENT, event.getLevel(), event.toTextMessage());
  }

  protected void storeLog(int eventType, AuditLevel level, String message) {
    Instant date = Instant.now();

    String payload = DTF.format(date.atZone(timeZone)) + DELIM + level.getText() + DELIM + eventType + DELIM + message;

    long ms = date.toEpochMilli();
    try {
      long size = Files.size(writerPath);
      if (ms > lastMsOfToday || size >= maxFileSize) {
        long oldLastOfToday = lastMsOfToday;

        Calendar now = Calendar.getInstance(TimeZone.getDefault());
        now.setTimeInMillis(ms);
        int yyyyMMddNow = DateUtil.getYyyyMMdd(now);
        lastMsOfToday = DateUtil.getLastMsOfDay(now);
        writer.close();

        if (oldLastOfToday == lastMsOfToday) {
          for (int i = 1; ;i++) {
            File renameTo = new File(logDir, writerFileCoreName + "-" + i + logFileNameSuffix);
            if (!renameTo.exists()) {
              writerPath.toFile().renameTo(renameTo);
              break;
            }
          }
        }

        writer = buildWriter(yyyyMMddNow);
      }

      writer.write(payload);
      writer.write('\n');
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
    }
  }

  private OutputStreamWriter buildWriter(int yyyyMMdd) {
    this.writerFileCoreName = buildFileCoreName(yyyyMMdd);
    File currentLogFile = new File(logDir, writerFileCoreName + logFileNameSuffix);
    OutputStream fw;
    try {
      fw = new FileOutputStream(currentLogFile, true);
    } catch (IOException ex) {
      throw new IllegalStateException("error opening file " + currentLogFile.getPath());
    }

    this.writerPath = currentLogFile.toPath();
    return new OutputStreamWriter(fw);
  }

  private String buildFileCoreName(int yyyyMMdd) {
    int year = yyyyMMdd / 10000;
    int month = yyyyMMdd % 10000 / 100;
    int day = yyyyMMdd % 100;
    String dateStr = year + "." + (month < 10 ? "0" + month : month) + "." + (day < 10 ? "0" + day : day);
    return logFileNamePrefix + dateStr;
  }

  @Override
  public void close() throws Exception {
    if (writer != null) {
      writer.flush();
      writer.close();
    }
  }

}
