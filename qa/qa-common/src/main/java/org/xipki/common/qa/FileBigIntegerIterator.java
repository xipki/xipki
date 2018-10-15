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

package org.xipki.common.qa;

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

import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.1.0
 */

public class FileBigIntegerIterator implements Iterator<BigInteger>, Closeable {

  private final boolean hex;

  private final boolean loop;

  private final String fileName;

  private BufferedReader reader;

  private ConcurrentLinkedQueue<BigInteger> nextNumbers = new ConcurrentLinkedQueue<>();

  private BigInteger currentNumber;

  public FileBigIntegerIterator(String fileName, boolean hex, boolean loop) throws IOException {
    this.fileName = ParamUtil.requireNonBlank("fileName", fileName);
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
      throw new NoSuchElementException("could not read next number from file " + fileName);
    }

    if (line.indexOf(',') == -1) {
      nextNumbers.add(new BigInteger(line.trim(), hex ? 16 : 10));
    } else {
      StringTokenizer st = new StringTokenizer(line.trim(), ", ");
      while (st.hasMoreTokens()) {
        nextNumbers.add(new BigInteger(st.nextToken(), hex ? 16 : 10));
      }
    }

    return nextNumbers.poll();
  }

  @Override
  public void close() {
    try {
      reader.close();
    } catch (Throwable th) {
      // STYLECHECK: SKIPTEST
    }
  }

}
