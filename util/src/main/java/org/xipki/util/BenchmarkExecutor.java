// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Benchmark executor.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public abstract class BenchmarkExecutor {

  public static final String PROPKEY_BENCHMARK = "org.xipki.benchmark";

  private static final int DEFAULT_DURATION = 30; // 30 seconds

  private static final int DEFAULT_THREADS = 25;

  private boolean interrupted;

  private final String description;

  private final ProcessLog processLog;

  private int duration = DEFAULT_DURATION; // in seconds

  private int threads = DEFAULT_THREADS;

  private final AtomicLong errorAccount = new AtomicLong(0);

  private String unit = "";

  public BenchmarkExecutor(String description) {
    this(description, 0);
  }

  public BenchmarkExecutor(String description, int total) {
    this.description = Args.notNull(description, "description");
    this.processLog = new ProcessLog(total);
  }

  protected abstract Runnable getTester() throws Exception;

  protected long getRealAccount(long account) {
    return account;
  }

  public void close() {
  }

  public void execute() {
    System.getProperties().setProperty(PROPKEY_BENCHMARK, "true");
    List<Runnable> runnables = new ArrayList<>(threads);
    for (int i = 0; i < threads; i++) {
      Runnable runnable;
      try {
        runnable = getTester();
      } catch (Exception ex) {
        System.err.println("could not initialize Tester: " + ex.getMessage());
        return;
      }

      runnables.add(runnable);
    }

    StringBuilder sb = new StringBuilder();
    if (StringUtil.isNotBlank(description)) {
      sb.append(description);
      char ch = description.charAt(description.length() - 1);
      if (ch != '\n') {
        sb.append('\n');
      }
    }
    sb.append("threads:  ").append(threads).append("\n");
    sb.append("duration: ").append(StringUtil.formatTime(duration, false)).append("\n");
    sb.append("unit:     ").append(unit).append("\n");
    sb.append("start at: ").append(ZonedDateTime.now().truncatedTo(ChronoUnit.MILLIS));

    System.out.println(sb);

    resetStartTime();

    ExecutorService executor = Executors.newFixedThreadPool(threads);
    for (Runnable runnable : runnables) {
      executor.execute(runnable);
    }

    executor.shutdown();
    printHeader();
    while (true) {
      printStatus();
      try {
        if (executor.awaitTermination(1, TimeUnit.SECONDS)) {
          break;
        }
      } catch (InterruptedException ex) {
        interrupted = true;
      }
    }

    printStatus();
    printSummary();

    close();
    System.getProperties().remove(PROPKEY_BENCHMARK);
  } // method test

  public boolean isInterrupted() {
    return interrupted;
  }

  public BenchmarkExecutor setDuration(String duration) {
    Args.notBlank(duration, "duration");
    char unit = duration.charAt(duration.length() - 1);

    String numStr;
    if (unit == 's' || unit == 'm' || unit == 'h') {
      numStr = duration.substring(0, duration.length() - 1);
    } else {
      unit = 's';
      numStr = duration;
    }

    int num;
    try {
      num = Integer.parseInt(numStr);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException("invalid duration " + duration);
    }

    if (num < 1) {
      throw new IllegalArgumentException("invalid duration " + duration);
    }

    if (unit == 's') {
      this.duration = num;
    } else if (unit == 'm') {
      this.duration = num * 60;
    } else { // if (unit == 'h') {
      this.duration = num * 3600; // 3600 = 60 * 60
    }

    return this;
  }

  public BenchmarkExecutor setThreads(int threads) {
    if (threads > 0) {
      this.threads = threads;
    }
    return this;
  }

  public long getErrorAccount() {
    return errorAccount.get();
  }

  public void account(long all, long failed) {
    processLog.addNumProcessed(getRealAccount(all));
    if (failed != 0) {
      errorAccount.addAndGet(getRealAccount(failed));
    }
  }

  public int getThreads() {
    return threads;
  }

  protected void resetStartTime() {
    processLog.reset();
  }

  protected boolean stop() {
    return interrupted || errorAccount.get() > 0
        || Duration.between(processLog.startTime(), Instant.now()).getSeconds() >= duration;
  }

  protected void printHeader() {
    processLog.printHeader();
  }

  protected void printStatus() {
    processLog.printStatus();
  }

  public BenchmarkExecutor setUnit(String unit) {
    this.unit = Args.notNull(unit, "unit");
    return this;
  }

  protected void printSummary() {
    processLog.printTrailer();

    String averageText = StringUtil.formatAccount(processLog.totalAverageSpeed(), 1);

    String msg = StringUtil.concatObjectsCap(400,
        " started at: ", processLog.startTime().atZone(ZoneOffset.systemDefault()),
        "\nfinished at: ", processLog.endTime().atZone(ZoneOffset.systemDefault()),
        "\n   duration: ", StringUtil.formatTime(processLog.totalElapsedTime().getSeconds(), false),
        "\n    account: ", StringUtil.formatAccount(processLog.numProcessed(), 1), " ", unit,
        "\n     failed: ", StringUtil.formatAccount(errorAccount.get(), 1), " ", unit,
        "\n    average: ", averageText, " ", unit, "/s\n");

    System.out.println(msg);
  }

  protected static long getSecureIndex() {
    while (true) {
      long nextLong = RandomUtil.nextLong();
      if (nextLong > 0) {
        return nextLong;
      }
    }
  }

}
