/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.common.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

public class FileBigIntegerIterator implements Iterator<BigInteger> {

    private final boolean hex;

    private final boolean loop;

    private final String fileName;

    private BufferedReader reader;

    private ConcurrentLinkedQueue<BigInteger> nextNumbers = new ConcurrentLinkedQueue<>();

    private BigInteger currentNumber;

    public FileBigIntegerIterator(String fileName, boolean hex, boolean loop)
            throws IOException {
        this.fileName = ParamUtil.requireNonBlank("fileName", fileName);
        this.hex = hex;
        this.loop = loop;
        this.reader = new BufferedReader(new FileReader(fileName));
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
                reader = new BufferedReader(new FileReader(fileName));
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

    public void close() {
        try {
            reader.close();
        } catch (Throwable th) {
            // STYLECHECK: SKIPTEST
        }
    }

}
