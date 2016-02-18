/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.pki.ca.common.test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.xipki.pki.ca.common.cmp.CmpUtf8Pairs;

import junit.framework.Assert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpUtf8PairsTest {

    @Test
    public void test1() {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a", "value-a");
        pairs.putUtf8Pair("key-b", "value-b");

        String expEncoded = "key-a?value-a%key-b?value-b%";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a");
        expNameValues.put("key-b", "value-b");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test2() {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%");

        String expEncoded = "key-a?value-a%";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test3() {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%");

        String expEncoded = "key-a?value-a%";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test4() {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%3f%");

        String expEncoded = "key-a?value-a%3f%";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a?");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test5() {
        CmpUtf8Pairs pairs = new CmpUtf8Pairs("key-a?value-a%3f%3f%25%");

        String expEncoded = "key-a?value-a%3f%3f%25%";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a??%");
        check(pairs, expEncoded, expNameValues);
    }

    private static void check(
            final CmpUtf8Pairs confPairs,
            final String expEncoded,
            final Map<String, String> expNameValues) {
        String iEncoded = confPairs.getEncoded();
        Assert.assertEquals("encoded", expEncoded, iEncoded);

        Set<String> iNames = confPairs.getNames();
        Assert.assertEquals("names", expNameValues.size(), iNames.size());

        for (String iName : iNames) {
            String expValue = expNameValues.get(iName);
            Assert.assertNotNull("name " + iName + " is not expected", expValue);
            Assert.assertEquals("value of name " + iName, expValue, confPairs.getValue(iName));
        }
    }

}
