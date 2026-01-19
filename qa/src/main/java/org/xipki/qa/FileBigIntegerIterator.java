// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa;

import org.xipki.util.codec.Args;
import org.xipki.util.misc.StringUtil;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Iterator which iterates the {@link BigInteger} specified in the file.
 *
 * @author Lijun Liao (xipki)
 * @since 2.1.0
 */

public class FileBigIntegerIterator implements Iterator<BigInteger>, Closeable {

  private final boolean hex;

  private final boolean loop;

  private final String fileName;

  private BufferedReader reader;

  private final ConcurrentLinkedQueue<BigInteger> nextNumbers =
      new ConcurrentLinkedQueue<>();

  private BigInteger currentNumber;

  public FileBigIntegerIterator(String fileName, boolean hex, boolean loop)
      throws IOException {
    this.fileName = Args.notBlank(fileName, "fileName");
    this.hex = hex;
    this.loop = loop;
    this.reader = Files.newBufferedReader(Paths.get(fileName));
    this.currentNumber = readNextNumber();
  }

  @Override
  public synchronized boolean hasNext() {
    return currentNumber != null;
  }

  @Override
  public synchronized BigInteger next() {
    if (currentNumber == null) {
      return null;
    }

    BigInteger ret = currentNumber;
    this.currentNumber = readNextNumber();
    return ret;
  }

  private BigInteger readNextNumber() {
    BigInteger number = nextNumbers.poll();
    if (number != null) {
      return number;
    }

    String line;
    try {
      line = reader.readLine();
      if (loop && line == null) {
        reader.close();
        reader = Files.newBufferedReader(Paths.get(fileName));
        line = reader.readLine();
      }

      if (line == null) {
        reader.close();
        return null;
      }
    } catch (IOException ex) {
      throw new NoSuchElementException("could not read next number from file "
          + fileName);
    }

    if (line.indexOf(',') == -1) {
      nextNumbers.add(StringUtil.toBigInt(line.trim(), hex));
    } else {
      StringTokenizer st = new StringTokenizer(line.trim(), ", ");
      while (st.hasMoreTokens()) {
        nextNumbers.add(StringUtil.toBigInt(st.nextToken(), hex));
      }
    }

    return nextNumbers.poll();
  } // method readNextNumber

  @Override
  public void close() {
    try {
      reader.close();
    } catch (Throwable th) {
    }
  }

}
