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

import java.io.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * The embedded audit service.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class EmbedAuditService implements AuditService {

  public static final String KEY_FILE = "file";

  private static final String DELIM = " | ";

  private static Logger LOG = LoggerFactory.getLogger(EmbedAuditService.class);

  private static final DateTimeFormatter DTF = DateTimeFormatter.ofPattern("yyyy.MM.dd-HH:mm:ss.SSS");

  private final ZoneId timeZone = ZoneId.systemDefault();

  private File logDir;

  private String logFileNamePrefix;

  private String logFileNameSuffix;

  private long lastMsOfToday;

  private OutputStreamWriter writer;

  public EmbedAuditService() {
  }

  @Override
  public void init(String conf) {
    try {
      init(conf, null);
    } catch (PasswordResolverException ex) {
      throw new IllegalStateException(ex);
    }
  }

  @Override
  public void init(String conf, PasswordResolver passwordResolver)
          throws PasswordResolverException {
    ConfPairs confPairs = new ConfPairs(conf);
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
    StringBuilder sb = new StringBuilder(message.length());

    sb.append(DTF.format(date.atZone(timeZone)))
            .append(DELIM).append(level.getText())
            .append(DELIM).append(eventType)
            .append(DELIM).append(message);

    String payload = sb.toString();

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

      writer.write(payload);
      writer.write('\n');
      writer.flush(); // TODO do not flush every time
    } catch (Exception ex) {
      LogUtil.error(LOG, ex);
    }
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
  public void close() throws Exception {
    writer.flush();
    writer.close();
  }

}
