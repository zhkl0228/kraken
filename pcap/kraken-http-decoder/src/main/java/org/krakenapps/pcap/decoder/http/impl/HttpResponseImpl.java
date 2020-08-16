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

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.krakenapps.pcap.decoder.http.HttpHeaders;
import org.krakenapps.pcap.decoder.http.HttpResponse;
import org.krakenapps.pcap.decoder.http.HttpVersion;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author mindori
 */
public class HttpResponseImpl extends Chunked implements HttpResponse {
	private final Logger logger = LoggerFactory.getLogger(HttpResponseImpl.class.getName());

	private final Buffer binary;

	private HttpVersion httpVersion;
	private int statusCode;
	private String reasonPhrase;
	private final Map<String, String> headers;

	/* flags represent to content type of http */
	private final EnumSet<FlagEnum> flags = EnumSet.of(FlagEnum.NONE);

	/* NORMAL variable */
	private int putLength = 0;

	/* MULTIPART, BYTERANGE variable */
	private String boundary;
	private int partLength = -1;

	/* GZIP variable */
	private int gzipOffset = 0;
	private int gzipLength = -1;

	private Buffer contentBuffer;
	private Buffer gzipContent;

	// private String contentStr;
	private byte[] content;
	private byte[] decompressedGzip;
	private byte[] chunkedBytes;
	private byte[] deflatedBytes;

	public void setDeflatedBytes(byte[] deflatedBytes) {
		this.deflatedBytes = deflatedBytes;
	}

	private String textContent;
	private InputStream inputStream;

	HttpResponseImpl() {
		binary = new ChainBuffer();
		headers = new LinkedHashMap<String, String>();
	}

	public void putBinary(Buffer data) {
		binary.addLast(data);
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
	public int getStatusCode() {
		return statusCode;
	}

	@Override
	public String getStatusLine() {
		return statusCode + " " + reasonPhrase;
	}

	public void setReasonPhrase(String reasonPhrase) {
		this.reasonPhrase = reasonPhrase;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	@Override
	public Set<String> getHeaderKeys() {
		return headers.keySet();
	}

	@Override
	public String getHeader(String name) {
		if (headers.containsKey(name))
			return headers.get(name);
		return null;
	}

	public void addHeader(String header) {
		int index = header.indexOf(':');
		if(index == -1) {
			headers.put(header, "");
		} else {
			headers.put(header.substring(0, index), header.substring(index + 1).trim());
		}
	}

	public EnumSet<FlagEnum> getFlags() {
		return flags;
	}

	@SuppressWarnings("unused")
	public int getPutLength() {
		return putLength;
	}

	public void addPutLength(int putLength) {
		this.putLength += putLength;
	}

	public String getBoundary() {
		return boundary;
	}

	public void setBoundary(String boundary) {
		this.boundary = boundary;
	}

	public int getPartLength() {
		return partLength;
	}

	public void setPartLength(int partLength) {
		this.partLength = partLength;
	}

	public int getGzipOffset() {
		return gzipOffset;
	}

	public void setGzipOffset(int gzipOffset) {
		this.gzipOffset = gzipOffset;
	}

	public int getGzipLength() {
		return gzipLength;
	}

	public void setGzipLength(int gzipLength) {
		this.gzipLength = gzipLength;
	}

	public void createContent() {
		contentBuffer = new ChainBuffer();
	}

	public Buffer getContentBuffer() {
		return contentBuffer;
	}

	public void createGzip() {
		gzipContent = new ChainBuffer();
	}

	public Buffer getGzip() {
		return gzipContent;
	}

	public void putGzip(Buffer buffer) {
		gzipContent.addLast(buffer);
	}

	public void setContent(byte[] content) {
		this.content = content;
	}

	public void setDecompressedGzip(byte[] decompressedGzip) {
		this.decompressedGzip = decompressedGzip;
	}

	public void setChunked(byte[] chunkedBytes) {
		this.chunkedBytes = chunkedBytes;
	}

	public InputStream getInputStream() {
		return inputStream;
	}

	@Override
	public String getContent() {
		return textContent;
	}

	public void setContent() throws IOException {
		String type = headers.get(HttpHeaders.CONTENT_TYPE);
		String charset = null;

		/* try to extract character set from 'Content-Type' field */
		if (type != null) {
			int charsetPos = type.indexOf("charset=");
			int boundary = type.indexOf(";");

			if (charsetPos != -1)
				charset = type.substring(charsetPos + 8);
			if (boundary != -1)
				type = type.substring(0, boundary);
		}

		mappingContents(type, charset);
	}

	private void mappingContents(String type, String charset) throws IOException {
		logger.debug("mappingContents type=" + type + ", charset=" + charset + ", chunkedBytes=" + (chunkedBytes == null ? null : chunkedBytes.length));
		if(flags.contains(FlagEnum.GZIP)) {
			if (decompressedGzip == null) {
				/* decompress failed */
				throw new IOException("kraken http decoder: gzip decoding failed");
			}
			
			inputStream = new ByteArrayInputStream(decompressedGzip);
		} else if(flags.contains(FlagEnum.CHUNKED)) {
			inputStream = new ByteArrayInputStream(chunkedBytes);
		} else if(flags.contains(FlagEnum.DEFLATE)) {
			inputStream = new ByteArrayInputStream(deflatedBytes);
		} else if(flags.contains(FlagEnum.BYTERANGE) || flags.contains(FlagEnum.NORMAL)) {
			if(content != null) {
				inputStream = new ByteArrayInputStream(content);
			} else if(contentBuffer != null) {
				byte[] buffer = new byte[contentBuffer.readableBytes()];
				contentBuffer.gets(buffer);
				inputStream = new ByteArrayInputStream(buffer);
			}
		}
		
		if (compareContentType(type)) {
			try {
				if (flags.contains(FlagEnum.GZIP)) {
					if (decompressedGzip == null) {
						/* decompress failed */
						throw new IOException("kraken http decoder: gzip decoding failed");
					} else {
						decodeNormalContent(charset, decompressedGzip);

					}
				} else if (flags.contains(FlagEnum.CHUNKED)) {
					decodeNormalContent(charset, chunkedBytes);
				} else if (flags.contains(FlagEnum.DEFLATE)) {
					decodeNormalContent(charset, deflatedBytes);
				} else if (flags.contains(FlagEnum.BYTERANGE)) {
					if (content != null)
						textContent = new String(content);
				} else if (flags.contains(FlagEnum.NORMAL)) {
					if (content == null) {
						return;
					}

					decodeNormalContent(charset, content);
				}
			} catch (UnsupportedEncodingException e) {
				if (logger.isDebugEnabled()) {
					logger.debug("kraken http decoder: unsupported encoding=" + charset, e);
				}
			}
		}
	}

	private void decodeNormalContent(String charset, byte[] content) throws UnsupportedEncodingException {
		if (charset != null)
			textContent = new String(content, charset);
		else {
			Charset ch = extractCharset(content);
			if (ch != null)
				textContent = new String(content, ch);
			else
				textContent = new String(content, Charset.defaultCharset());
		}
	}

	/* try to extract character set from <META> tag */
	private Charset extractCharset(byte[] content) {
		if (content == null)
			return null;

		String s;

		if (content.length > 1024)
			s = new String(content, 0, 1024);
		else if (content.length > 200)
			s = new String(content, 0, 200);
		else
			return null;

		/* avoid upper case characters */
		s = s.toLowerCase();

		String charset = parseCharset(s, "<meta");
		if (charset == null) {
			charset = parseCharset(s, "<script");
			if (charset == null) {
				charset = parseCharsetFromCss(s);
			}
		}

		if (charset != null) {
			try {
				return Charset.forName(charset.replaceAll("\"", "").replaceAll("/", "").trim());
			} catch (IllegalCharsetNameException e) {
				return null;
			}
		}

		return null;
	}

	private String parseCharset(String content, String indexStr) {
		int i = content.indexOf(indexStr);
		if (i != -1) {
			int j = content.indexOf("charset");
			if (j != -1) {
				int k = j + 8;
				while (k < content.length()) {
					if (content.charAt(k) == '"' || content.charAt(k) == '>')
						break;
					k++;
				}

				return content.substring(j + 8, k);
			}
		}
		return null;
	}

	private String parseCharsetFromCss(String content) {
		int j = content.indexOf("@charset");
		if (j != -1) {
			int k = j + 10;
			while (k < content.length()) {
				if (content.charAt(k) == '"')
					break;
				k++;
			}

			return content.substring(j + 10, k);
		}
		return null;
	}

	private boolean compareContentType(String type) {
		if(type == null)
			return false;
		
		List<String> contentTypes = new ArrayList<String>();

		contentTypes.add("text/css");
		contentTypes.add("text/html");
		contentTypes.add("text/javascript");
		contentTypes.add("text/plain");
		contentTypes.add("text/xml");
		contentTypes.add("application/x-javascript");
		contentTypes.add("application/javascript");
		contentTypes.add("application/xml");
		contentTypes.add("application/octet-stream");
		
		contentTypes.add("application/json");

		return contentTypes.contains(type);
	}
}