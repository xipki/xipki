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

package org.xipki.ca.server.mgmt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

public class AddLicense {
	
	private final static String licenseText =
	 "/*\n" +
	 " * ====================================================================\n" +
	 " * Licensed to the Apache Software Foundation (ASF) under one\n" +
	 " * or more contributor license agreements.  See the NOTICE file\n" +
	 " * distributed with this work for additional information\n" +
	 " * regarding copyright ownership.  The ASF licenses this file\n" +
	 " * to you under the Apache License, Version 2.0 (the\n" +
	 " * \"License\"); you may not use this file except in compliance\n" +
	 " * with the License.  You may obtain a copy of the License at\n" +
	 " *\n" +
	 " *   http://www.apache.org/licenses/LICENSE-2.0\n" +
	 " *\n" +
	 " * Unless required by applicable law or agreed to in writing,\n" +
	 " * software distributed under the License is distributed on an\n" +
	 " * \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n" +
	 " * KIND, either express or implied.  See the License for the\n" +
	 " * specific language governing permissions and limitations\n" +
	 " * under the License.\n" +
	 " * ====================================================================\n" +
	 " *\n" +
	 " * This work is part of XiPKI, owned by Lijun Liao (lijun.liao@gmail.com)\n" +
	 " *\n" +
	 " */\n\n";
	
	public static void main(String[] args) {
		try{
			String dirName = args[0];
			
			File dir = new File(dirName);
			addLicenseToDir(dir);			
		}catch(Exception e)
		{
			e.printStackTrace();
		}
	}

	private static void addLicenseToDir(File dir) throws Exception
	{
		File[] files = dir.listFiles();
		for(File file : files)
		{
			if(file.isDirectory())
			{
				addLicenseToDir(file);
			}
			else if(file.isFile() && file.getName().endsWith(".java"))
			{
				addLicenseToFile(file);
			}
		}
	}
	
	private static void addLicenseToFile(File file) throws Exception
	{
		System.out.println(file.getPath());
		BufferedReader reader = new BufferedReader(new FileReader(file));
		
		File newFile = new File(file.getPath() + "-new");
		BufferedWriter writer = new BufferedWriter(new FileWriter(newFile));
		
		try{
			String line;
			boolean skip = true;
			while((line = reader.readLine()) != null)
			{
				if(line.trim().startsWith("package "))
				{
					writer.write(licenseText);
					skip = false;
				}
				
				if(!skip)
				{
					writer.write(line);
					writer.write('\n');
				}
			}
		}finally
		{
			writer.close();
			reader.close();
		}
		
		newFile.renameTo(file);
		
	}

}
