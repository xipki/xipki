/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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

import org.junit.Test;
import org.xipki.commons.common.HealthCheckResult;

import junit.framework.Assert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HealthCheckResultTest {

    @Test
    public void test1() {
        String encoded = "{\"healthy\":true}";
        HealthCheckResult result = HealthCheckResult.getInstanceFromJsonMessage("default",
                encoded);

        String noPrettyJson = "{\"healthy\":true}";

        String prettyJson =
            "{\n"
            + "    \"healthy\":true\n"
            + "}";
        check(result, noPrettyJson, prettyJson);
    }

    @Test
    public void test2() {
        String encoded = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
                + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},"
                + "\"childcheck2\":{\"healthy\":false}}}";

        HealthCheckResult result = HealthCheckResult.getInstanceFromJsonMessage("default",
                encoded);

        String noPrettyJson = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
                + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},"
                + "\"childcheck2\":{\"healthy\":false}}}";

        String prettyJson =
                "{\n"
                + "    \"healthy\":true,\n"
                + "    \"checks\":{\n"
                + "        \"childcheck\":{\n"
                + "            \"healthy\":false,\n"
                + "            \"checks\":{\n"
                + "                \"childChildCheck\":{\n"
                + "                    \"healthy\":false\n"
                + "                }\n"
                + "            }\n"
                + "        },\n"
                + "        \"childcheck2\":{\n"
                + "            \"healthy\":false\n"
                + "        }\n"
                + "    }\n"
                + "}";

        check(result, noPrettyJson, prettyJson);
    }

    @Test
    public void test3() {
        HealthCheckResult result = new HealthCheckResult("mycheck-negative");
        result.setHealthy(false);

        String noPrettyJson = "{\"healthy\":false}";

        String prettyJson =
                "{\n"
                + "    \"healthy\":false\n"
                + "}";
        check(result, noPrettyJson, prettyJson);
    }

    @Test
    public void test4() {
        HealthCheckResult result = new HealthCheckResult("mycheck-positive");
        result.setHealthy(true);

        String noPrettyJson = "{\"healthy\":true}";

        String prettyJson =
                "{\n"
                + "    \"healthy\":true\n"
                + "}";
        check(result, noPrettyJson, prettyJson);
    }

    @Test
    public void test5() {
        HealthCheckResult result = new HealthCheckResult("mycheck-positive");
        result.setHealthy(true);

        HealthCheckResult childCheck = new HealthCheckResult("childcheck");
        result.addChildCheck(childCheck);
        childCheck.setHealthy(false);

        HealthCheckResult childCheck2 = new HealthCheckResult("childcheck2");
        result.addChildCheck(childCheck2);
        childCheck.setHealthy(false);

        HealthCheckResult childChildCheck = new HealthCheckResult("childChildCheck");
        childCheck.addChildCheck(childChildCheck);
        childChildCheck.setHealthy(false);

        String noPrettyJson = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
                + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},\"childcheck2\":"
                + "{\"healthy\":false}}}";

        String prettyJson =
                "{\n"
                + "    \"healthy\":true,\n"
                + "    \"checks\":{\n"
                + "        \"childcheck\":{\n"
                + "            \"healthy\":false,\n"
                + "            \"checks\":{\n"
                + "                \"childChildCheck\":{\n"
                + "                    \"healthy\":false\n"
                + "                }\n"
                + "            }\n"
                + "        },\n"
                + "        \"childcheck2\":{\n"
                + "            \"healthy\":false\n"
                + "        }\n"
                + "    }\n"
                + "}";
        check(result, noPrettyJson, prettyJson);
    }

    private static void check(
            final HealthCheckResult result,
            final String expNoPrettyJson,
            final String expPrettyJson) {
        Assert.assertEquals("non-pretty JSON", expNoPrettyJson, result.toJsonMessage(false));
        Assert.assertEquals("pretty JSON", expPrettyJson, result.toJsonMessage(true));
    }

}
