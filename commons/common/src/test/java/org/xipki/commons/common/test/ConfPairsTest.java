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

package org.xipki.commons.common.test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.xipki.commons.common.ConfPairs;

import junit.framework.Assert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ConfPairsTest {

    @Test
    public void test1() {
        ConfPairs pairs = new ConfPairs("key-a?", "value-a=");
        pairs.putPair("key-b", "value-b");

        String expEncoded = "key-a?=value-a\\=,key-b=value-b";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a?", "value-a=");
        expNameValues.put("key-b", "value-b");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test2() {
        ConfPairs pairs = new ConfPairs("key-a=value-a");

        String expEncoded = "key-a=value-a";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test3() {
        ConfPairs pairs = new ConfPairs("key-empty-value=");

        String expEncoded = "key-empty-value=";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-empty-value", "");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test4() {
        ConfPairs pairs = new ConfPairs("key-empty-value=,key-b=value-b");

        String expEncoded = "key-b=value-b,key-empty-value=";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-b", "value-b");
        expNameValues.put("key-empty-value", "");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test5() {
        ConfPairs pairs = new ConfPairs("key-a=value-a\\,");

        String expEncoded = "key-a=value-a\\,";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a,");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test6() {
        ConfPairs pairs = new ConfPairs("key-a=value-a\\=\\,");

        String expEncoded = "key-a=value-a\\=\\,";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a=,");
        check(pairs, expEncoded, expNameValues);
    }

    @Test
    public void test7() {
        ConfPairs pairs = new ConfPairs("key-a=value-a\\=\\?");

        String expEncoded = "key-a=value-a\\=?";
        Map<String, String> expNameValues = new HashMap<>();
        expNameValues.put("key-a", "value-a=?");
        check(pairs, expEncoded, expNameValues);
    }

    private static void check(
            final ConfPairs confPairs,
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
