/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)
 *
 */

package org.xipki.ca.server.mgmt.shell;

import java.io.IOException;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.security.common.CmpUtf8Pairs;
import org.xipki.security.common.IoCertUtil;

class ShellUtil {
	static String replaceFileInSignerConf(String signerConf) throws IOException
	{
		if(signerConf.contains("file:") == false)
		{
			return signerConf;
		}
		
		CmpUtf8Pairs utf8Pairs = new CmpUtf8Pairs(signerConf);
		for(String name : utf8Pairs.getNames())
		{
			String value = utf8Pairs.getValue(name);
			if(value.startsWith("file:"))
			{
				String fn = value.substring("file:".length());
				byte[] fileContent = IoCertUtil.read(fn);
				value = Base64.toBase64String(fileContent);
				utf8Pairs.putUtf8Pair(name, "base64:" + value);
			}
		}
		
		return utf8Pairs.getEncoded();
	}
}
