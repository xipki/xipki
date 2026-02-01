// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.mgmt.db.diffdb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Report of the comparison result of two databases.
 *
 * @author Lijun Liao (xipki)
 */

class DigestDiffReporter implements Closeable {

  private static final Logger LOG =
      LoggerFactory.getLogger(DigestDiffReporter.class);

  private final String reportDirname;

  private final SynchronizedWriter goodWriter;

  private final BufferedWriter diffWriter;

  private final SynchronizedWriter missingWriter;

  private final SynchronizedWriter unexpectedWriter;

  private final BufferedWriter errorWriter;

  private Instant startTime;

  private final AtomicInteger numGood = new AtomicInteger(0);

  private final AtomicInteger numDiff = new AtomicInteger(0);

  private final AtomicInteger numMissing = new AtomicInteger(0);

  private final AtomicInteger numUnexpected = new AtomicInteger(0);

  private final AtomicInteger numError = new AtomicInteger(0);

  public DigestDiffReporter(String reportDirname, byte[] caCertBytes)
      throws IOException {
    this.reportDirname = Args.notBlank(reportDirname, "reportDirname");
    File dir = new File(reportDirname);
    IoUtil.mkdirs(dir);
    IoUtil.save(new File(dir, "ca.der"), caCertBytes);

    String dirPath = dir.getPath();

    this.missingWriter    = new SynchronizedWriter(Files.newBufferedWriter(
                              Paths.get(dirPath, "missing")));
    this.unexpectedWriter = new SynchronizedWriter(Files.newBufferedWriter(
                              Paths.get(dirPath, "unexpected")));
    this.goodWriter       = new SynchronizedWriter(Files.newBufferedWriter(
                              Paths.get(dirPath, "good")));
    this.diffWriter  = Files.newBufferedWriter(Paths.get(dirPath, "diff"));
    this.errorWriter = Files.newBufferedWriter(Paths.get(dirPath, "error"));

    start();
  } // constructor

  public final void start() {
    startTime = Instant.now();
  }

  public String reportDirname() {
    return reportDirname;
  }

  public void addMissing(BigInteger serialNumber) throws IOException {
    numMissing.incrementAndGet();
    missingWriter.writeSerialNumber(serialNumber);
  }

  public void addGood(BigInteger serialNumber) throws IOException {
    numGood.incrementAndGet();
    goodWriter.writeSerialNumber(serialNumber);
  }

  public void addUnexpected(BigInteger serialNumber) throws IOException {
    numUnexpected.incrementAndGet();
    unexpectedWriter.writeSerialNumber(serialNumber);
  }

  public void addDiff(DigestEntry refCert, DigestEntry targetCert)
      throws IOException {
    if (Args.notNull(refCert, "refCert").serialNumber().equals(
        Args.notNull(targetCert, "targetCert").serialNumber())) {
      throw new IllegalArgumentException(
          "refCert and targetCert are not of the same serialNumber");
    }

    numDiff.incrementAndGet();
    String msg = StringUtil.concat(refCert.serialNumber().toString(16),
        "\t", refCert.encodedOmitSerialNumber(), "\t",
        targetCert.encodedOmitSerialNumber(), "\n");
    synchronized (diffWriter) {
      diffWriter.write(msg);
    }
  } // method addDiff

  public void addError(String errorMessage) throws IOException {
    String msg = StringUtil.concat(
        Args.notNull(errorMessage, "errorMessage"), "\n");
    numError.incrementAndGet();
    synchronized (errorWriter) {
      errorWriter.write(msg);
    }
  } // method addError

  public void addNoCaMatch() throws IOException {
    synchronized (errorWriter) {
      errorWriter.write("could not find corresponding CA in target to diff\n");
    }
  }

  @Override
  public void close() {
    closeWriter(missingWriter, unexpectedWriter, diffWriter,
        goodWriter, errorWriter);

    int sum = numGood.get() + numDiff.get() + numMissing.get()
              + numUnexpected.get() + numError.get();
    Instant now = Instant.now();
    int durationSec = (int) (now.getEpochSecond() - startTime.getEpochSecond());

    String speedStr = (durationSec > 0)
        ? StringUtil.formatAccount(sum / durationSec, false) + " /s" : "--";

    String str = StringUtil.concatObjectsCap(200,
        "      sum : ", StringUtil.formatAccount(sum, false),
        "\n      good: ", StringUtil.formatAccount(numGood.get(), false),
        "\n      diff: ", StringUtil.formatAccount(numDiff.get(), false),
        "\n   missing: ", StringUtil.formatAccount(numMissing.get(), false),
        "\nunexpected: ", StringUtil.formatAccount(numUnexpected.get(), false),
        "\n     error: ", StringUtil.formatAccount(numError.get(), false),
        "\n  duration: ", StringUtil.formatTime(durationSec, false),
        "\nstart time: ", startTime,
        "\n  end time: ", now,
        "\n     speed: ", speedStr, "\n");

    try {
      IoUtil.save(reportDirname + File.separator + "overview.txt",
          StringUtil.toUtf8Bytes(str));
    } catch (IOException ex) {
      System.out.println("Could not write overview.txt with following " +
          "content\n" + str);
    }
  } // method close

  private static void closeWriter(Closeable... closeables) {
    for (Closeable cloz : closeables) {
      try {
        cloz.close();
      } catch (Exception ex) {
        LogUtil.warn(LOG, ex, "could not close closable " + cloz);
      }
    }
  } // method closeWriter

  private static class SynchronizedWriter implements Closeable {
    private final BufferedWriter underlying;

    public SynchronizedWriter(BufferedWriter underlying) {
      this.underlying = underlying;
    }

    public synchronized void writeSerialNumber(BigInteger serialNumber)
        throws IOException {
      underlying.write(StringUtil.concat(serialNumber.toString(16), "\n"));
    }

    @Override
    public synchronized void close() throws IOException {
      underlying.close();
    }
  }

}
