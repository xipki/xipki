/*
 * Copyright 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.remotep11.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.xipki.security.api.SignerException;
import org.xipki.security.common.ParamChecker;

class DefaultRemoteP11CryptService extends RemoteP11CryptService {
	private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";
	private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

	private URL serverUrl;
	
	@SuppressWarnings("unused")
	private String user;
	@SuppressWarnings("unused")
	private char[] password;
	
	DefaultRemoteP11CryptService(String url, String user, char[] password) 
	{
		ParamChecker.assertNotEmpty("url", url);
		
		this.user = user;
		this.password = password;
		
		try {
			this.serverUrl = new URL(url);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid url: " + serverUrl);
		}
	}

	@Override
    public byte[] send(byte[] request)
    throws IOException    
    {
		HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
    	httpUrlConnection.setDoOutput(true);
		httpUrlConnection.setUseCaches(false);
	
    	int size = request.length;
    	
    	httpUrlConnection.setRequestMethod("POST");
    	httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
    	httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
    	OutputStream outputstream = httpUrlConnection.getOutputStream();
    	outputstream.write(request);
    	outputstream.flush();
    	InputStream inputstream = httpUrlConnection.getInputStream();
    	try{
	    	if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) 
	    	{
	    	    throw new IOException("Bad Response: "
	    	            + httpUrlConnection.getResponseCode() + "  "
	    	            + httpUrlConnection.getResponseMessage());
	    	}
	    	String responseContentType=httpUrlConnection.getContentType();
	    	boolean isValidContentType=false;
	    	if (responseContentType!=null)
	    	{
	   	        if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE))
	   	        {
	   	        	isValidContentType=true;
	    	    }
	    	}
	    	if (isValidContentType==false)
	    	{
	    	    throw new IOException("Bad Response: Mime type "
	    	    		+ responseContentType
	    	    		+ " not supported!");
	    	}
	
	    	byte[] buf = new byte[4096];
	    	ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
	    	do 
	    	{
	    	    int j = inputstream.read(buf);
	    	    if (j == -1) 
	    	    {
	    	        break;
	    	    }
	    	    bytearrayoutputstream.write(buf, 0, j);
	    	} while (true);

	    	return bytearrayoutputstream.toByteArray();
    	}finally{
    		inputstream.close();
    	}
    }

	@Override
	public void refresh() throws SignerException {		
	}

}
