/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.ca.dbtool.diffdb;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

class DigestDiffReporter {

  private static final Logger LOG = LoggerFactory.getLogger(DigestDiffReporter.class);

  private final String reportDirname;

  private final BufferedWriter goodWriter;

  private final BufferedWriter diffWriter;

  private final BufferedWriter missingWriter;

  private final BufferedWriter unexpectedWriter;

  private final BufferedWriter errorWriter;

  private Date startTime;

  private AtomicInteger numGood = new AtomicInteger(0);

  private AtomicInteger numDiff = new AtomicInteger(0);

  private AtomicInteger numMissing = new AtomicInteger(0);

  private AtomicInteger numUnexpected = new AtomicInteger(0);

  private AtomicInteger numError = new AtomicInteger(0);

  public DigestDiffReporter(String reportDirname, byte[] caCertBytes) throws IOException {
    this.reportDirname = ParamUtil.requireNonBlank("reportDirname", reportDirname);
    File dir = new File(reportDirname);
    dir.mkdirs();
    IoUtil.save(new File(dir, "ca.der"), caCertBytes);

    this.missingWriter = new BufferedWriter(new FileWriter(new File(dir, "missing")));
    this.unexpectedWriter = new BufferedWriter(new FileWriter(new File(dir, "unexpected")));
    this.diffWriter = new BufferedWriter(new FileWriter(new File(dir, "diff")));
    this.goodWriter = new BufferedWriter(new FileWriter(new File(dir, "good")));
    this.errorWriter = new BufferedWriter(new FileWriter(new File(dir, "error")));

    start();
  }

  public void start() {
    startTime = new Date();
  }

  public String getReportDirname() {
    return reportDirname;
  }

  public void addMissing(BigInteger serialNumber) throws IOException {
    numMissing.incrementAndGet();
    writeSerialNumberLine(missingWriter, serialNumber);
  }

  public void addGood(BigInteger serialNumber) throws IOException {
    numGood.incrementAndGet();
    writeSerialNumberLine(goodWriter, serialNumber);
  }

  public void addUnexpected(BigInteger serialNumber) throws IOException {
    numUnexpected.incrementAndGet();
    writeSerialNumberLine(unexpectedWriter, serialNumber);
  }

  public void addDiff(DigestEntry refCert, DigestEntry targetCert) throws IOException {
    ParamUtil.requireNonNull("refCert", refCert);
    ParamUtil.requireNonNull("targetCert", targetCert);

    if (refCert.getSerialNumber().equals(targetCert.getSerialNumber())) {
      throw new IllegalArgumentException("refCert and targetCert are not of the same serialNumber");
    }

    numDiff.incrementAndGet();
    String msg = StringUtil.concat(refCert.getSerialNumber().toString(16),
        "\t", refCert.encodedOmitSeriaNumber(), "\t", targetCert.encodedOmitSeriaNumber(), "\n");
    synchronized (diffWriter) {
      diffWriter.write(msg);
    }
  }

  public void addError(String errorMessage) throws IOException {
    ParamUtil.requireNonNull("errorMessage", errorMessage);

    numError.incrementAndGet();
    String msg = StringUtil.concat(errorMessage, "\n");
    synchronized (errorWriter) {
      errorWriter.write(msg);
    }
  }

  public void addNoCaMatch() throws IOException {
    synchronized (errorWriter) {
      errorWriter.write("could not find corresponding CA in target to diff\n");
    }
  }

  public void close() {
    closeWriter(missingWriter);
    closeWriter(unexpectedWriter);
    closeWriter(diffWriter);
    closeWriter(goodWriter);
    closeWriter(errorWriter);

    int sum = numGood.get() + numDiff.get() + numMissing.get() + numUnexpected.get()
              + numError.get();
    Date now = new Date();
    int durationSec = (int) ((now.getTime() - startTime.getTime()) / 1000);

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
      IoUtil.save(reportDirname + File.separator + "overview.txt", str.getBytes());
    } catch (IOException ex) {
      System.out.println("Could not write overview.txt with following content\n" + str);
    }
  } // method close

  private static void writeSerialNumberLine(BufferedWriter writer, BigInteger serialNumber)
      throws IOException {
    String msg = StringUtil.concat(serialNumber.toString(16), "\n");
    synchronized (writer) {
      writer.write(msg);
    }
  }

  private static void closeWriter(Writer writer) {
    try {
      writer.close();
    } catch (Exception ex) {
      LogUtil.warn(LOG, ex, "could not close writer");
    }
  }

}
