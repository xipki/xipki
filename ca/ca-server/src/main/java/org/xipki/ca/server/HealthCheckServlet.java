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

package org.xipki.ca.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.server.mgmt.CAManager;
import org.xipki.security.common.HealthCheckResult;

public class HealthCheckServlet extends HttpServlet
{
	private static final Logger LOG = LoggerFactory.getLogger(HealthCheckServlet.class);
	
	private static final long serialVersionUID = 1L;
	
	private static final String CT_RESPONSE = "application/json";
	
	private CAManager caManager;	
	
	public HealthCheckServlet()
	{
	}

	@Override
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException 
    {
		try{
			if(caManager == null)
			{
				LOG.error("caManager in servlet not configured");			
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.setContentLength(0);
				return;
			}		

			String encodedUrl = request.getRequestURI();
			String constructedPath = null;
			if (encodedUrl != null)
			{
				constructedPath = URLDecoder.decode(encodedUrl, "UTF-8");
				String servletPath = request.getServletPath();
				if(! servletPath.endsWith("/"))
				{
					servletPath += "/";
				}
				
				int indexOf = constructedPath.indexOf(servletPath);
				if (indexOf >= 0) {
					constructedPath = constructedPath.substring(indexOf+servletPath.length());
				}
			}

			int caAlias_end_index = constructedPath.indexOf('/');
			String caAlias = (caAlias_end_index == -1) ?
					constructedPath : constructedPath.substring(0, caAlias_end_index);

			String caName = caManager.getCaName(caAlias);
			if(caName == null)
			{
				caName = caAlias;
			}
			
			X509CACmpResponder responder = caManager.getX509CACmpResponder(caName);
			if(responder == null || responder.isCAInService() == false)
			{
				if(responder == null)
				{
					LOG.warn("Unknown CA {}", caName);
				}
				else
				{
					LOG.warn("CA {} is out of service", caName);
				}
				
				response.setContentLength(0);
				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
				response.flushBuffer();
				return;
			}

			HealthCheckResult healthResult = responder.healthCheck();
			if (healthResult.isHealthy()) {
				response.setStatus(HttpServletResponse.SC_OK);
			} else {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			}

			response.setContentType(HealthCheckServlet.CT_RESPONSE);
			byte[] respBytes = healthResult.toJsonMessage(true).getBytes();
			response.setContentLength(respBytes.length);
			response.getOutputStream().write(respBytes);
		}catch(Throwable t)
		{
			LOG.error("Throwable thrown, this should not happen!", t);
			response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			response.setContentLength(0);
		}
		
		response.flushBuffer();
	}

	protected PKIMessage generatePKIMessage(InputStream is) throws IOException
	{
		ASN1InputStream asn1Stream = new ASN1InputStream(is);
		
		try{
			return PKIMessage.getInstance(asn1Stream.readObject());
		}finally{
			try{
				asn1Stream.close();
			}catch(IOException e){}
		}
	}
	
	public CAManager getCaManager() {
		return caManager;
	}

	public void setCaManager(CAManager caManager) {
		this.caManager = caManager;
	}
}
