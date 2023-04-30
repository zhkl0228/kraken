/**
 * 
 */
package org.krakenapps.pcap.decoder.http.h2;

import org.krakenapps.pcap.decoder.http.HttpVersion;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

/**
 * @author zhkl0228
 *
 */
public class Http2ResponseImpl implements Http2Response {

	private static final Logger log = LoggerFactory.getLogger(Http2ResponseImpl.class);

	private final Map<String, String> headers;
	final Buffer buffer;
	private final int statusCode;
	private final String statusLine;

	public Http2ResponseImpl(Map<String, String> headers) {
		super();
		this.headers = headers;
		this.buffer = new ChainBuffer();
		this.statusLine = headers.remove(":status");
		int index = statusLine == null ? -1 : statusLine.indexOf(' ');
		if(index == -1) {
			try {
				this.statusCode = statusLine == null ? -1 : Integer.parseInt(statusLine);
			} catch(NumberFormatException e) {
				throw new IllegalStateException("invalid status line: " + statusLine);
			}
		} else {
			this.statusCode = Integer.parseInt(statusLine.substring(0, index));
		}

		log.debug("Http2ResponseImpl headers={}", headers);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getStatusCode()
	 */
	@Override
	public int getStatusCode() {
		return statusCode;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getStatusLine()
	 */
	@Override
	public String getStatusLine() {
		return statusLine;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getHttpVersion()
	 */
	@Override
	public HttpVersion getHttpVersion() {
		return HttpVersion.HTTP_2_0;
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getHeaderKeys()
	 */
	@Override
	public Set<String> getHeaderKeys() {
		return headers.keySet();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getHeader(java.lang.String)
	 */
	@Override
	public String getHeader(String name) {
		return headers.get(name);
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getContent()
	 */
	@Override
	public String getContent() {
		return null;
	}

	private byte[] responseEntity;

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.http.HttpResponse#getInputStream()
	 */
	@Override
	public InputStream getInputStream() {
		if(responseEntity == null) {
			String contentEncoding = getHeader("content-encoding");
			responseEntity = Http2Stream.extractBuffer(contentEncoding, buffer);
		}

		return new ByteArrayInputStream(responseEntity);
	}

}
