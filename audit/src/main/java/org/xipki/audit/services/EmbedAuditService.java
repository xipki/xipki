// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.audit.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.audit.AuditEvent;
import org.xipki.audit.AuditLevel;
import org.xipki.audit.AuditService;
import org.xipki.audit.PciAuditEvent;
import org.xipki.util.ConfPairs;
import org.xipki.util.DateUtil;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.exception.InvalidConfException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The embedded audit service.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class EmbedAuditService implements AuditService {

  public static final String KEY_FILE = "file";

  public static final String KEY_SIZE = "size";

  private static final String DELIM = " | ";

  private static final Logger LOG = LoggerFactory.getLogger(EmbedAuditService.class);

  private static final DateTimeFormatter DTF = DateTimeFormatter.ofPattern("yyyy.MM.dd-HH:mm:ss.SSS");

  private final ZoneId timeZone = ZoneId.systemDefault();

  private File logDir;

  private String logFileNamePrefix;

  private String logFileNameSuffix;

  private Instant lastMsOfToday;

  private int maxFileSize;

  private OutputStreamWriter writer;

  private Path writerPath;

  private String writerFileCoreName;

  private final AtomicLong lastFlushed = new AtomicLong();

  public EmbedAuditService() {
  }

  @Override
  public void init(ConfPairs conf) throws InvalidConfException {
    if (conf == null) {
      conf = new ConfPairs();
    }
    String str = conf.value(KEY_SIZE);

    final int mb = 1024 * 1024;

    if (str == null) {
      this.maxFileSize = 10 * mb; // 10 MB
    } else {
      str = str.trim().toLowerCase(Locale.ROOT);
      int value = Integer.parseInt(str.substring(0, str.length() - 2).trim());
      if (str.endsWith("gb")) {
        this.maxFileSize = value * 1024 * mb;
      } else if (str.endsWith("mb")) {
        this.maxFileSize = value * mb;
      } else if (str.endsWith("kb")) {
        this.maxFileSize = value * 1024;
      } else {
        this.maxFileSize = Integer.parseInt(str);
      }

      if (this.maxFileSize < mb) {
        throw new InvalidConfException("invalid size " + str);
      }
    }

    String logFilePath = conf.value(KEY_FILE);

    logFilePath = StringUtil.isBlank(logFilePath)
        ? "logs/audit.log" : StringUtil.resolveVariables(logFilePath);
    logFilePath = IoUtil.expandFilepath(logFilePath, true);

    File logFile = new File(logFilePath).getAbsoluteFile();
    this.logDir = logFile.getParentFile();
    try {
      IoUtil.mkdirs(this.logDir);
    } catch (IOException e) {
      throw new InvalidConfException("error mkdirs for " + this.logDir.getPath());
    }

    String fileName = logFile.getName();
    int idx = fileName.lastIndexOf('.');
    logFileNameSuffix = idx == -1 ? "" : fileName.substring(idx);

    String prefix = idx == -1 ? fileName : fileName.substring(0, idx);
    this.logFileNamePrefix = prefix + "_";

    // analyze the existing log files
    ZonedDateTime now = ZonedDateTime.now();
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

    try {
      long size = Files.size(writerPath);
      if (date.isAfter(lastMsOfToday) || size >= maxFileSize) {
        Instant oldLastOfToday = lastMsOfToday;

        ZonedDateTime now = ZonedDateTime.ofInstant(date, ZoneId.systemDefault());
        int yyyyMMddNow = DateUtil.getYyyyMMdd(now);
        lastMsOfToday = DateUtil.getLastMsOfDay(now);
        writer.flush();
        writer.close();

        if (oldLastOfToday == lastMsOfToday) {
          for (int i = 1; ;i++) {
            File renameTo = new File(logDir, writerFileCoreName + "-" + i + logFileNameSuffix);
            if (!renameTo.exists()) {
              IoUtil.renameTo(writerPath.toFile(), renameTo);
              break;
            }
          }
        }

        writer = buildWriter(yyyyMMddNow);
      }

      writer.write(payload);
      writer.write('\n');

      long now = Clock.systemUTC().millis();
      if (now > lastFlushed.get() + 10000) { // 10 seconds
        writer.flush();
        lastFlushed.set(now);
      }
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
