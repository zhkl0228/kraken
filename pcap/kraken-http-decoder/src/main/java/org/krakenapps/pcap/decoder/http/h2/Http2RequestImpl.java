package org.krakenapps.pcap.decoder.http.h2;

import edu.baylor.cs.csi5321.spdy.frames.SpdyNameValueBlock;
import org.krakenapps.pcap.decoder.http.HttpMethod;
import org.krakenapps.pcap.decoder.http.HttpVersion;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author zhkl0228
 *
 */
public class Http2RequestImpl implements Http2Request {

	private static final Logger log = LoggerFactory.getLogger(Http2RequestImpl.class);

	private final HttpSessionImpl session;
	private final Map<String, String> headers;
	final Buffer buffer;
	private final URL url;
	private final HttpMethod method;

	Http2RequestImpl(HttpSessionImpl session, SpdyNameValueBlock nameValueBlock) {
		super();
		this.session = session;
		this.headers = new LinkedHashMap<String, String>(nameValueBlock.getPairs());
		this.buffer = new ChainBuffer();

		StringBuilder buffer = new StringBuilder();
		buffer.append(headers.remove(":scheme")).append("://");
		buffer.append(headers.get(":authority")).append(headers.remove(":path"));
		try {
			url = new URL(buffer.toString());
		} catch (MalformedURLException e) {
			throw new IllegalStateException("the url is: " + buffer, e);
		}

		if(url.getQuery() != null) {
			setParameters(url.getQuery());
		}

		this.method = HttpMethod.valueOf(headers.remove(":method"));
		log.debug("Http2RequestImpl headers=" + headers);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getHttpVersion()
	 */
	@Override
	public HttpVersion getHttpVersion() {
		return HttpVersion.HTTP_2_0;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getURL()
	 */
	@Override
	public URL getURL() {
		return url;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getQueryString()
	 */
	@Override
	public String getQueryString() {
		return url.getQuery();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getMethod()
	 */
	@Override
	public HttpMethod getMethod() {
		return method;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getRemoteAddress()
	 */
	@Override
	public InetSocketAddress getServerAddress() {
		TcpSessionKey key = session.getKey();
		return new InetSocketAddress(key.getServerIp(), key.getServerPort());
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getLocalAddress()
	 */
	@Override
	public InetSocketAddress getClientAddress() {
		TcpSessionKey key = session.getKey();
		return new InetSocketAddress(key.getClientIp(), key.getClientPort());
	}

	private final Map<String, String> parameters = new HashMap<String, String>();

	private void setParameters(String queryString) {
		String[] params = queryString.split("&");
		for (String param : params) {
			String[] token = param.split("=");
			if (token.length == 2)
				parameters.put(token[0], token[1]);
			else if (token.length == 1)
				parameters.put(token[0], null);
		}
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#containsParameter(java.lang.String)
	 */
	@Override
	public boolean containsParameter(String key) {
		return parameters.containsKey(key);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getParameter(java.lang.String)
	 */
	@Override
	public String getParameter(String key) {
		return parameters.get(key);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getHeaderKeys()
	 */
	@Override
	public Set<String> getHeaderKeys() {
		return headers.keySet();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#containsHeader(java.lang.String)
	 */
	@Override
	public boolean containsHeader(String name) {
		return headers.containsKey(name);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getHeader(java.lang.String)
	 */
	@Override
	public String getHeader(String name) {
		return headers.get(name);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getTextContent()
	 */
	@Override
	public String getTextContent() {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getFileNames()
	 */
	@Override
	public Set<String> getFileNames() {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getFile(java.lang.String)
	 */
	@Override
	public InputStream getFile(String fileName) {
		throw new UnsupportedOperationException();
	}

	private byte[] requestEntity;

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpRequest#getRequestEntity()
	 */
	@Override
	public byte[] getRequestEntity() {
		if(requestEntity == null) {
			requestEntity = new byte[buffer.readableBytes()];
			buffer.gets(requestEntity);
		}

		return requestEntity;
	}

}
