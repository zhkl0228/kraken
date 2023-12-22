/*
 * Copyright 2010 NCHOVY
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
package org.krakenapps.pcap.decoder.http.impl;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.HttpHeaders;
import org.krakenapps.pcap.decoder.http.HttpMethod;
import org.krakenapps.pcap.decoder.http.HttpRequest;
import org.krakenapps.pcap.decoder.http.HttpVersion;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author mindori
 */
public class HttpRequestImpl extends Chunked implements HttpRequest {

	// connection metadata
	private final InetSocketAddress client;
	private final InetSocketAddress server;

	private HttpMethod method;
	private String path;
	private String queryString;
	private HttpVersion httpVersion;

	public final Map<String, String> headers;
	private final Map<String, String> parameters;

	/* flags represent to content type of http */
	private final EnumSet<FlagEnum> flags = EnumSet.of(FlagEnum.NONE);

	// multipart variable
	private byte[] endBoundary;

	private final Map<String, InputStream> files;
	
	private final Protocol protocol;

	HttpRequestImpl(InetSocketAddress client, InetSocketAddress server, Protocol protocol) {
		super();
		
		this.client = client;
		this.server = server;
		this.protocol = protocol;

		headers = new LinkedHashMap<String, String>();
		parameters = new LinkedHashMap<String, String>();
		files = new LinkedHashMap<String, InputStream>();
	}

	public EnumSet<FlagEnum> getFlags() {
		return flags;
	}

	@Override
	public InetSocketAddress getServerAddress() {
		return server;
	}

	@Override
	public InetSocketAddress getClientAddress() {
		return client;
	}

	@Override
	public HttpMethod getMethod() {
		return method;
	}

	public void setMethod(String method) {
		if (method.equals("OPTIONS"))
			this.method = HttpMethod.OPTIONS;
		else if (method.equals("GET"))
			this.method = HttpMethod.GET;
		else if (method.equals("HEAD"))
			this.method = HttpMethod.HEAD;
		else if (method.equals("POST"))
			this.method = HttpMethod.POST;
		else if (method.equals("PUT"))
			this.method = HttpMethod.PUT;
		else if (method.equals("DELETE"))
			this.method = HttpMethod.DELETE;
		else if (method.equals("TRACE"))
			this.method = HttpMethod.TRACE;
		else if (method.equals("CONNECT"))
			this.method = HttpMethod.CONNECT;
	}

	public URL getURL() {
		String host = null;
		for(String key : getHeaderKeys()) {
			if(key.equalsIgnoreCase(HttpHeaders.HOST)) {
				host = getHeader(key);
				break;
			}
		}
		if (host == null) {
			host = server.getAddress().getHostAddress();
		} else {
			host = host.replaceAll("\n", "");
		}
		
		String scheme = "http";
		if(protocol == Protocol.SSL) {
			scheme = "https";
		}

		try {
			if (host.equals(path)) {
				path = "/";
			}

			return new URI(scheme, host, path, queryString, null).toURL();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("scheme=" + scheme + ", host=" + host + ", path=" + path + ", queryString=" + queryString, e);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("scheme=" + scheme + ", host=" + host + ", path=" + path + ", queryString=" + queryString, e);
		}
	}

	@Override
	public String getQueryString() {
		return queryString;
	}

	public void setPath(String path) {
		if(path.toLowerCase().startsWith("http://") || path.toLowerCase().startsWith("https://")) {
			try {
				URL url = new URL(path);
				this.path = url.getPath();
				this.queryString = url.getQuery();
				if(this.queryString != null) {
					setParameters();
				}
			} catch(MalformedURLException e) {
				throw new IllegalArgumentException(path, e);
			}
			return;
		}
		
		this.path = path;
		int queryStrOffset = path.indexOf("?");
		if (queryStrOffset != -1) {
			this.path = path.substring(0, queryStrOffset);
			queryString = path.substring(queryStrOffset + 1);
			setParameters();
		} else {
			queryString = null;
		}
	}

	public Set<String> getParameterKeys() {
		return parameters.keySet();
	}

	@Override
	public boolean containsParameter(String key) {
		return parameters.containsKey(key);
	}

	@Override
	public String getParameter(String key) {
		if (parameters.containsKey(key)) {
			return parameters.get(key);
		}
		return null;
	}

	public void addParameter(String key, String value) {
		parameters.put(key, value);
	}

	private void setParameters() {
		String[] params = queryString.split("&");
		for (String param : params) {
			String[] token = param.split("=");
			if (token.length == 2)
				parameters.put(token[0], token[1]);
			else if (token.length == 1)
				parameters.put(token[0], null);
		}
	}

	@Override
	public HttpVersion getHttpVersion() {
		return httpVersion;
	}

	public void setHttpVersion(String httpVersion) {
		if (httpVersion.equals("HTTP/1.1"))
			this.httpVersion = HttpVersion.HTTP_1_1;
		else
			this.httpVersion = HttpVersion.HTTP_1_0;
	}

	@Override
	public Set<String> getHeaderKeys() {
		return headers.keySet();
	}

	@Override
	public boolean containsHeader(String name) {
		return headers.containsKey(name);
	}

	@Override
	public String getHeader(String name) {
		if (headers.containsKey(name)) {
			return headers.get(name);
		}
		return null;
	}

	public final boolean isWebSocket() {
		return isWebSocket(headers);
	}

	static boolean isWebSocket(Map<String, String> headers) {
		String connection = null;
		String upgrade = null;
		for (Map.Entry<String, String> entry : headers.entrySet()) {
			if ("Connection".equalsIgnoreCase(entry.getKey())) {
				connection = entry.getValue();
			} else if ("Upgrade".equalsIgnoreCase(entry.getKey())) {
				upgrade = entry.getValue();
			}
		}
		return "Upgrade".equalsIgnoreCase(connection) && "websocket".equalsIgnoreCase(upgrade);
	}

	public void addHeader(String header) {
		String[] token = header.split(": ");
		String headerName = HttpHeaders.canonicalize(token[0]);

		if(token.length == 1) {
			headers.put(headerName, "");
		}
		else if( token[1] == null ) {
			headers.put(headerName, "");
		}
		else {
			headers.put(headerName, token[1]);
		}
	}

	public byte[] getEndBoundary() {
		return endBoundary;
	}

	public void setEndBoundary(byte[] endBoundary) {
		this.endBoundary = endBoundary;
	}

	@Override
	public String getTextContent() {
		return null;
	}

	@Override
	public Set<String> getFileNames() {
		return files.keySet();
	}

	@Override
	public InputStream getFile(String fileName) {
		return files.get(fileName);
	}
	
	private byte[] requestEntity;

	@Override
	public byte[] getRequestEntity() {
		return requestEntity;
	}

	public void setRequestEntity(byte[] requestEntity) {
		this.requestEntity = requestEntity;
	}
	
}
