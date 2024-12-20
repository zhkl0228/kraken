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
package org.krakenapps.pcap.decoder.http;

import com.twitter.hpack.Decoder;
import edu.baylor.cs.csi5321.spdy.frames.H2DataFrame;
import edu.baylor.cs.csi5321.spdy.frames.H2Exception;
import edu.baylor.cs.csi5321.spdy.frames.H2Frame;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameGoAway;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameHeaders;
import edu.baylor.cs.csi5321.spdy.frames.H2FramePing;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameRstStream;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameSettings;
import edu.baylor.cs.csi5321.spdy.frames.H2FrameWindowUpdate;
import edu.baylor.cs.csi5321.spdy.frames.H2PriorityFrame;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.h2.Http2Stream;
import org.krakenapps.pcap.decoder.http.impl.Chunked;
import org.krakenapps.pcap.decoder.http.impl.FlagEnum;
import org.krakenapps.pcap.decoder.http.impl.HttpRequestImpl;
import org.krakenapps.pcap.decoder.http.impl.HttpRequestState;
import org.krakenapps.pcap.decoder.http.impl.HttpResponseImpl;
import org.krakenapps.pcap.decoder.http.impl.HttpResponseState;
import org.krakenapps.pcap.decoder.http.impl.HttpSession;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.decoder.http.impl.PartialContentManager;
import org.krakenapps.pcap.decoder.http.impl.WebSocketFrameImpl;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.BufferUnderflowException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

enum HttpDirection {
	REQUEST, RESPONSE
}

/**
 * @author mindori
 */
public class HttpDecoder implements TcpProcessor {

	public static final int DECODE_NOT_READY = -1;
	private final Logger logger = LoggerFactory.getLogger(HttpDecoder.class.getName());

	private final Set<HttpProcessor> callbacks;
	private final Map<TcpSessionKey, HttpSessionImpl> sessionMap;

	private final PartialContentManager mpManager;

	public HttpDecoder() {
		callbacks = new HashSet<>();
		sessionMap = new HashMap<>();
		mpManager = new PartialContentManager();
	}

	private TcpProcessor tcpVisitor;

	public void setTcpVisitor(TcpProcessor tcpVisitor) {
		this.tcpVisitor = tcpVisitor;
	}

	public void register(HttpProcessor processor) {
		callbacks.add(processor);
	}

	public void unregister(HttpProcessor processor) {
		callbacks.remove(processor);
	}

	@Override
	public void handleTx(TcpSessionKey sessionKey, Buffer data) {
		if (tcpVisitor != null) {
			tcpVisitor.handleTx(sessionKey, data);
		}

		HttpSessionImpl session = sessionMap.get(sessionKey);
		if (session == null) {
			return;
		}

		TcpProcessor fallbackTcpProcessor = session.getFallbackTcpProcessor();
		if(fallbackTcpProcessor != null) {
			fallbackTcpProcessor.handleTx(sessionKey, data);
			return;
		}

        if(log.isDebugEnabled()) {
            data.mark();
            byte[] bytes = new byte[data.readableBytes()];
            data.gets(bytes);
            data.reset();
            log.debug("handleTx sessionKey={}, session={}, data={}", new Object[]{sessionKey, session, HexFormatter.encodeHexString(bytes)});
        }

		try {
			handleRequest(session, data);
		} catch (DataFormatException | IOException e) {
			throw new IllegalStateException("handleRequest", e);
		}
    }

	private TcpProcessor fallbackTcpProcessor;

	public void setFallbackTcpProcessor(TcpProcessor fallbackTcpProcessor) {
		this.fallbackTcpProcessor = fallbackTcpProcessor;
	}

	@Override
	public void handleRx(TcpSessionKey sessionKey, Buffer data) {
		if(tcpVisitor != null) {
			tcpVisitor.handleRx(sessionKey, data);
		}

		HttpSessionImpl session = sessionMap.get(sessionKey);
		if (session == null) {
			return;
		}
		TcpProcessor fallbackTcpProcessor = session.getFallbackTcpProcessor();
		if (fallbackTcpProcessor != null) {
			fallbackTcpProcessor.handleRx(sessionKey, data);
			return;
		}

		if(log.isDebugEnabled()) {
			data.mark();
			byte[] bytes = new byte[data.readableBytes()];
			data.gets(bytes);
			data.reset();
			// log.debug("handleRx sessionKey=" + sessionKey + ", session=" + session + ", data=" + HexFormatter.encodeHexString(bytes));
		}

		handleResponse(session, data);
	}

	@Override
	public boolean onEstablish(TcpSession session) {
		if(tcpVisitor != null) {
			tcpVisitor.onEstablish(session);
		}

		TcpSessionKey sessionKey = session.getKey();
		Protocol protocol = session.getProtocol();
		if (logger.isDebugEnabled()) {
            logger.debug("-> Http Session Established: {} -> {}, protocol={}", new Object[]{sessionKey.getClientPort(), sessionKey.getServerPort(), protocol});
		}
		InetAddress clientIp = sessionKey.getClientIp();
		InetAddress serverIp = sessionKey.getServerIp();
		InetSocketAddress clientAddr = new InetSocketAddress(clientIp, sessionKey.getClientPort());
		InetSocketAddress serverAddr = new InetSocketAddress(serverIp, sessionKey.getServerPort());
		HttpSessionImpl impl = new HttpSessionImpl(session, clientAddr, serverAddr);
		if (protocol == Protocol.HTTP2) {
			impl.setHttp2();
		} else if (protocol == Protocol.SSL && fallbackTcpProcessor != null) {
			if (fallbackTcpProcessor.onEstablish(session)) {
				impl.setFallbackTcpProcessor(fallbackTcpProcessor);
			}
		}
		sessionMap.put(sessionKey, impl);
		return true;
	}

	@Override
	public void onFinish(TcpSessionKey session) {
		if(tcpVisitor != null) {
			tcpVisitor.onFinish(session);
		}

		HttpSessionImpl httpSession = sessionMap.remove(session);
		TcpProcessor fallbackTcpProcessor = httpSession == null ? null : httpSession.getFallbackTcpProcessor();
		if (fallbackTcpProcessor != null) {
			fallbackTcpProcessor.onFinish(session);
			return;
		}

		try {
			handleNoContentLengthCase(httpSession);
		} catch (IOException e) {
			logger.debug(e.getMessage(), e);
		}

		if (logger.isDebugEnabled())
            logger.debug("-> Http Session Closed: \nClient Port: {}\nServer Port: {}", session.getClientPort(), session.getServerPort());
	}

	@Override
	public void onReset(TcpSessionKey session) {
		if(tcpVisitor != null) {
			tcpVisitor.onReset(session);
		}

		HttpSessionImpl httpSession = sessionMap.remove(session);
		TcpProcessor fallbackTcpProcessor = httpSession == null ? null : httpSession.getFallbackTcpProcessor();
		if (fallbackTcpProcessor != null) {
			fallbackTcpProcessor.onReset(session);
			return;
		}

		try {
			handleNoContentLengthCase(httpSession);
		} catch (IOException e) {
			logger.debug(e.getMessage(), e);
		}

		if (httpSession == null) {
			return;
		}

		httpSession.deallocate();

		if (logger.isDebugEnabled())
			logger.debug("Deallocate tx, rx buffer and remove Http session.");
	}

	private void handleNoContentLengthCase(HttpSessionImpl httpSession) throws IOException {
		if (httpSession != null && httpSession.getResponseState() == HttpResponseState.GOT_HEADER) {
			decodeContent(httpSession.getResponse());
			dispatchResponse(httpSession);
		}
	}

	private void handleRequest(HttpSessionImpl session, Buffer data) throws DataFormatException, IOException {
		Buffer txBuffer = session.getTxBuffer();
		txBuffer.addLast(data);
		parseRequest(session, txBuffer);
	}

	private void handleResponse(HttpSessionImpl session, Buffer data) {
		int capacity = data.readableBytes();
		Buffer rxBuffer = session.getRxBuffer();
		rxBuffer.addLast(data);
		try {
			parseResponse(session, rxBuffer, data, capacity);
		} catch (DataFormatException | IOException e) {
			logger.debug(e.getMessage(), e);
		}
	}

	private void parseRequest(HttpSessionImpl session, Buffer txBuffer) throws DataFormatException {
		if (session.getRequest() == null) {
			session.createRequest();
		}

		if (session.isWebSocket()) {
			parseWebSocketRequest(session, txBuffer);
			return;
		}
		if (session.isHttp2() && session.httpPrefaceRead) {
			parseHttp2Request(session, txBuffer);
			return;
		}

		HttpRequestImpl request = session.getRequest();

		/* multiple requests in a session. */
		if (session.getRequestState() == HttpRequestState.END) {
            session.setRequestState(HttpRequestState.READY);
        }

		while (session.getRequestState() != HttpRequestState.END) {
			switch (session.getRequestState()) {
				case READY:
				case GOT_METHOD:
					try {
						txBuffer.mark();

						int len = txBuffer.bytesBefore(new byte[] { 0x20 });
						if (len == 0) {
							if (session.getRequestState() == HttpRequestState.READY && txBuffer.readableBytes() >= 4 && fallbackTcpProcessor != null) { // invalid http
								log.debug("http fallback");
								fallbackTcpProcessor.onEstablish(session);
								fallbackTcpProcessor.handleTx(session.getKey(), txBuffer);
								session.setFallbackTcpProcessor(fallbackTcpProcessor);
							}
							return;
						}

						byte[] t = new byte[len];
						txBuffer.gets(t);

						/* skip space */
						txBuffer.get();

						if (session.getRequestState() == HttpRequestState.READY) {
							boolean isValidHttp = len < 10;
							String method = new String(t);
							if ("PRI".equals(method)) {
								if (txBuffer.readableBytes() < 20) {
									throw new IllegalStateException("Invalid http/2.0");
								}
								byte[] http2 = new byte[20];
								txBuffer.gets(http2);
								if ("* HTTP/2.0\r\n\r\nSM\r\n\r\n".equals(new String(http2))) {
									session.httpPrefaceRead = true;
									session.setHttp2();
									parseHttp2Request(session, txBuffer);
									return;
								} else {
									throw new IllegalStateException("Invalid http/2.0: " + HexFormatter.encodeHexString(http2));
								}
							}

							if(fallbackTcpProcessor != null) {
								if(isValidHttp) {
									isValidHttp = false;
									for (HttpMethod httpMethod : HttpMethod.values()) {
										if (httpMethod.name().equalsIgnoreCase(method)) {
											isValidHttp = true;
											break;
										}
									}
								}
								if(!isValidHttp) {
									log.debug("http fallback isValidHttp=false");
									txBuffer.reset();
									fallbackTcpProcessor.onEstablish(session);
									fallbackTcpProcessor.handleTx(session.getKey(), txBuffer);
									session.setFallbackTcpProcessor(fallbackTcpProcessor);
									return;
								}
							}

							if (log.isDebugEnabled()) {
                                log.debug("parseRequest method={}", method);
							}
							request.setMethod(method);
							session.setRequestState(HttpRequestState.GOT_METHOD);
						} else {
                        String path = new String(t);
							if (log.isDebugEnabled()) {
                                log.debug("parseRequest path={}", path);
							}
							request.setPath(path);
							session.setRequestState(HttpRequestState.GOT_URI);
						}

					} catch (BufferUnderflowException e) {
						txBuffer.reset();
						return;
					}
					break;

				case GOT_URI:
					try {
						byte[] t = scanHttpLine(txBuffer);
						if (t == null) {
							return;
						}

						request.setHttpVersion(new String(t));
						session.setRequestState(HttpRequestState.GOT_HTTP_VER);
					} catch (BufferUnderflowException e) {
						txBuffer.reset();
						return;
					}
					break;

				case GOT_HTTP_VER:
					try {
						byte[] t = scanHttpLine(txBuffer);
						if (t == null) {
							return;
						}

                    String header = new String(t);
						request.addHeader(header);

						txBuffer.mark();
						byte s2 = txBuffer.get();
						byte s3 = txBuffer.get();
						if (s2 == 0x0d && s3 == 0x0a) {
							session.setRequestState(HttpRequestState.GOT_HEADER);
						} else {
							txBuffer.reset();
						}

                        log.debug("Parse http request header: {}, state: {}", header, session.getRequestState());
					} catch (BufferUnderflowException e) {
						txBuffer.reset();
						return;
					}
					break;

				case GOT_HEADER:
					/* Get body of request */
					EnumSet<FlagEnum> flag = request.getFlags();

					/* Classify request type */
					if ((flag.size() <= 1) && (flag.contains(FlagEnum.NONE))) {
						txBuffer.mark();
						setRequestType(request);
					}
					if (log.isDebugEnabled()) {
                        log.debug("parseRequest state={}, flag={}, sessionKey={}", new Object[]{session.getResponseState(), flag, session.getKey()});
					}

					if (request.containsHeader(HttpHeaders.CONTENT_LENGTH)) {
						int contentLength = Integer.parseInt(request.getHeader(HttpHeaders.CONTENT_LENGTH));
						if (txBuffer.readableBytes() < contentLength) {
							return;
						}

						// read request body
						byte[] body = new byte[txBuffer.readableBytes()];
						txBuffer.gets(body);
						request.setRequestEntity(body);
						parseRequestBody(request, body);
					} else if (flag.contains(FlagEnum.CHUNKED)) {
						int retVal = handleChunked(request, txBuffer, session, request, null);
						if (log.isDebugEnabled()) {
                            log.debug("handleChunked ret={}, trunkedLength={}", retVal, request.getChunkedLength());
						}

						if (retVal == DECODE_NOT_READY) {
							txBuffer.reset();
							return;
						} else if (retVal == 0) {
							return;
						} else {
							// read request body
							byte[] body = request.readChunkedBytes();
							if (log.isDebugEnabled()) {
                                log.debug("parseRequest state={}, flag={}, body={}", new Object[]{session.getResponseState(), flag, HexFormatter.encodeHexString(body)});
							}
							if (flag.contains(FlagEnum.GZIP)) {
								byte[] decompressed = decompressGzip(new ChainBuffer(body));
								request.setRequestEntity(decompressed);
							} else {
								request.setRequestEntity(body);
							}

							parseRequestBody(request, body);
						}
					}

					dispatchRequest(session, request);
					session.setRequestState(HttpRequestState.END);
					break;
				case END:
					break;
			}
		}
	}

	private void parseHttp2Request(HttpSessionImpl session, Buffer txBuffer) {
		if (log.isDebugEnabled()) {
			try {
				txBuffer.mark();
				byte[] data = new byte[txBuffer.readableBytes()];
				txBuffer.gets(data);
				log.debug("parseHttp2Request session={}, data={}", session.getKey(), HexFormatter.encodeHexString(data));
			} finally {
				txBuffer.reset();
			}
		}

		try {
			H2Frame frame;
			while ((frame = decodeFrame(session, txBuffer, session.txHpackDecoder)) != null) {
				parseClientSpdyFrame(session, frame);
			}
		} catch(H2Exception e) {
			log.warn("parseHttp2Request spdy", e);
		}
	}

	private void parseHttp2Response(HttpSessionImpl session, Buffer rxBuffer) {
		if (log.isDebugEnabled()) {
			try {
				rxBuffer.mark();
				byte[] data = new byte[rxBuffer.readableBytes()];
				rxBuffer.gets(data);
				log.debug("parseHttp2Response session={}, data={}", session.getKey(), HexFormatter.encodeHexString(data));
			} finally {
				rxBuffer.reset();
			}
		}

		try {
			H2Frame frame;
			while ((frame = decodeFrame(session, rxBuffer, session.rxHpackDecoder)) != null) {
				parseServerSpdyFrame(session, frame);
			}
		} catch(H2Exception e) {
			log.warn("parseHttp2Response spdy", e);
		}
	}

	private void parseClientSpdyFrame(HttpSessionImpl session, H2Frame frame) {
		log.debug("parseClientSpdyFrame session={}, frame={}", session, frame);

		if (frame instanceof H2FrameSettings) {
			H2FrameSettings settings = (H2FrameSettings) frame;
			int maxHeaderTableSize = settings.getHeaderTableSize();
			if (session.txHpackDecoder == null) {
				int maxHeaderSize = settings.getMaxHeaderListSize();
				session.txHpackDecoder = new Decoder(maxHeaderSize, maxHeaderTableSize);
			} else {
				session.txHpackDecoder.setMaxHeaderTableSize(maxHeaderTableSize);
			}
			return;
		}
		if (frame instanceof H2FrameWindowUpdate) {
			return;
		}
		if (frame instanceof H2FramePing) {
			return;
		}
		if (frame instanceof H2FrameGoAway) {
			return;
		}
		if (frame instanceof H2PriorityFrame) {
			return;
		}
		if (frame instanceof H2FrameHeaders) {
			H2FrameHeaders frameHeaders = (H2FrameHeaders) frame;
			if (!frameHeaders.hasFlag(H2Frame.FLAG_END_HEADERS)) {
				throw new UnsupportedOperationException();
			}
			Http2Stream stream = new Http2Stream(session, callbacks);
			stream.handleRequestHeaders(frameHeaders);
			session.http2StreamMap.put(frameHeaders.getStreamId(), stream);
		} else if (frame instanceof H2DataFrame) {
			H2DataFrame dataFrame = (H2DataFrame) frame;
			Http2Stream stream = session.http2StreamMap.get(dataFrame.getStreamId());
			if (stream == null) {
				log.warn("parseClientSpdyFrame: {}, http2StreamMap={}", frame, session.http2StreamMap);
				return;
			}
			stream.handleRequestData(dataFrame);
		} else if (frame instanceof H2FrameRstStream) {
			H2FrameRstStream frameRstStream = (H2FrameRstStream) frame;
			switch (frameRstStream.getStatusCode()) {
				case CANCEL:
				case STREAM_CLOSED:
					break;
				case NO_ERROR:
				default:
					throw new UnsupportedOperationException("frame=" + frame);
			}
		} else {
			throw new UnsupportedOperationException("session=" + session + ", frame=" + frame);
		}
	}

	private void parseServerSpdyFrame(HttpSessionImpl session, H2Frame frame) {
		log.debug("parseServerSpdyFrame session={}, frame={}", session, frame);

		if (frame instanceof H2FrameSettings) {
			H2FrameSettings settings = (H2FrameSettings) frame;
			int maxHeaderTableSize = settings.getHeaderTableSize();
			if (session.rxHpackDecoder == null) {
				int maxHeaderSize = settings.getMaxHeaderListSize();
				session.rxHpackDecoder = new Decoder(maxHeaderSize, maxHeaderTableSize);
			} else {
				session.rxHpackDecoder.setMaxHeaderTableSize(maxHeaderTableSize);
			}
			return;
		}
		if (frame instanceof H2FrameWindowUpdate) {
			return;
		}
		if (frame instanceof H2FrameGoAway) {
			return;
		}
		if (frame instanceof H2FramePing) {
			return;
		}
		if (frame instanceof H2FrameHeaders) {
			H2FrameHeaders frameHeaders = (H2FrameHeaders) frame;
			if (!frameHeaders.hasFlag(H2Frame.FLAG_END_HEADERS)) {
				throw new UnsupportedOperationException();
			}
			Http2Stream stream = session.http2StreamMap.get(frameHeaders.getStreamId());
			if (stream == null) {
				log.warn("parseServerSpdyFrame: {}, http2StreamMap={}", frame, session.http2StreamMap);
				return;
			}
			if (stream.handleResponseHeaders(frameHeaders)) {
				session.http2StreamMap.remove(frameHeaders.getStreamId());
			}
		} else if (frame instanceof H2DataFrame) {
			H2DataFrame dataFrame = (H2DataFrame) frame;
			Http2Stream stream = session.http2StreamMap.get(dataFrame.getStreamId());
			if (stream == null) {
				log.warn("parseServerSpdyFrame NOT found stream: {}", dataFrame.getStreamId());
				return;
			}
			if (stream.handleResponseData(dataFrame)) {
				session.http2StreamMap.remove(dataFrame.getStreamId());
			}
		} else if (frame instanceof H2FrameRstStream) {
			H2FrameRstStream frameRstStream = (H2FrameRstStream) frame;
			switch (frameRstStream.getStatusCode()) {
				case CANCEL:
				case NO_ERROR:
				case STREAM_CLOSED:
				case PROTOCOL_ERROR:
					session.http2StreamMap.remove(frameRstStream.getStreamId());
					break;
				default:
					throw new UnsupportedOperationException("frame=" + frame);
			}
		} else {
			throw new UnsupportedOperationException("session=" + session + ", frame=" + frame);
		}
	}

	private static H2Frame decodeFrame(HttpSessionImpl impl, Buffer buffer, Decoder hpackDecoder) throws H2Exception {
		H2Frame frame = H2Frame.decodeBuffer(impl, buffer, hpackDecoder);
		if (frame != null) {
			log.debug("decodeFrame: {}", frame);
		}
		return frame;
	}

	private void parseWebSocketRequest(HttpSessionImpl session, Buffer txBuffer) {
		if (session.txFrame == null) {
			session.txFrame = new WebSocketFrameImpl();
		}
		if (decodeWebSocketFrame(session.txFrame, txBuffer)) {
			for (HttpProcessor processor : callbacks) {
				processor.onWebSocketRequest(session, session.txFrame);
			}
			session.txFrame = null;
		}
	}

	private void parseWebSocketResponse(HttpSessionImpl session, Buffer rxBuffer) {
		if (session.rxFrame == null) {
			session.rxFrame = new WebSocketFrameImpl();
		}
		if (decodeWebSocketFrame(session.rxFrame, rxBuffer)) {
			for (HttpProcessor processor : callbacks) {
				processor.onWebSocketResponse(session, session.rxFrame);
			}
			session.rxFrame = null;
		}
	}

	private boolean decodeWebSocketFrame(WebSocketFrameImpl frame, Buffer buffer) {
		if (frame.length == DECODE_NOT_READY) {
			if (buffer.readableBytes() < 2) {
				return false;
			}
			buffer.mark();
			byte b1 = buffer.get();
			byte b2 = buffer.get();
			long len = b2 & 0x7f;
			if (len == 126 && buffer.readableBytes() >= 2) {
				if (buffer.readableBytes() >= 2) {
					len = buffer.getUnsignedShort();
				} else {
					buffer.reset();
					return false;
				}
			} else if (len == 127) {
				if (buffer.readableBytes() >= 8) {
					len = buffer.getLong();
				} else {
					buffer.reset();
					return false;
				}
			}
			boolean mask = ((b2 >> 7) & 1) == 1;
			if (mask) {
				if (buffer.readableBytes() >= 4) {
					byte[] maskingKey = new byte[4];
					buffer.gets(maskingKey);
					frame.maskingKey = maskingKey;
				} else {
					buffer.reset();
					return false;
				}
			}

			boolean fin = ((b1 >> 7) & 1) == 1;
			boolean rsv1 = ((b1 >> 6) & 1) == 1;
			boolean rsv2 = ((b1 >> 5) & 1) == 1;
			boolean rsv3 = ((b1 >> 4) & 1) == 1;
			int opcode = b1 & 0xf;
			frame.length = len;
			frame.fin = fin;
			frame.rsv1 = rsv1;
			frame.rsv2 = rsv2;
			frame.rsv3 = rsv3;
			frame.opcode = WebSocketFrame.OpCode.valueOf(opcode);
		} else if (buffer.readableBytes() >= frame.length) {
			byte[] bytes = new byte[(int) frame.length];
			buffer.gets(bytes);
			frame.payload = bytes;
			frame.decodePayload();
			return true;
		}
		return false;
	}

	private byte[] scanHttpLine(Buffer buffer) {
		int len = buffer.bytesBefore(new byte[] { 0x0d, 0x0a });
		if (len == 0) {
			return null;
		}

		byte[] bytes = new byte[len];
		buffer.gets(bytes);

		/* skip \r\n */
		buffer.get();
		buffer.get();
		return bytes;
	}

	private void parseRequestBody(HttpRequestImpl request, byte[] body) {
		if (request.containsHeader(HttpHeaders.CONTENT_TYPE) && !request.containsHeader(HttpHeaders.CONTENT_ENCODING)) {
			String[] tokens = request.getHeader(HttpHeaders.CONTENT_TYPE).split(";");
			if (tokens[0].equalsIgnoreCase("application/x-www-form-urlencoded")) {
				parseUrlEncodedParams(request, body, tokens);
			}
		}
	}

	private static final Logger log = LoggerFactory.getLogger(HttpDecoder.class);

	private void parseUrlEncodedParams(HttpRequestImpl request, byte[] body, String[] tokens) {
		// determine body encoding
		String encoding = "utf-8";
		for (int i = 1; i < tokens.length; i++) {
			if (tokens[i].startsWith("charset="))
				encoding = tokens[i].substring("charset=".length());
		}

		// split parameters
		Charset charset = Charset.forName(encoding);
		String content = new String(body, charset);
		String[] args = content.split("&");
		for (String arg : args) {
			String[] pair = arg.split("=");
			try {
				String key = URLDecoder.decode(pair[0], encoding);
				String value = null;
				if (pair.length > 1) {
                    value = URLDecoder.decode(pair[1], encoding);
                }
				request.addParameter(key, value);
			} catch (UnsupportedEncodingException ignored) {
			} catch(java.lang.IllegalArgumentException e) {
				if (log.isDebugEnabled()) {
                    log.debug("parseUrlEncodedParams failed: remoteAddress={}", request.getServerAddress(), e);
				}
				return;
			}
		}
	}

	private void parseResponse(HttpSessionImpl session, Buffer rxBuffer, Buffer data, int capacity) throws DataFormatException, IOException {
		if (session.getResponse() == null) {
			session.createResponse();
		}

		if (session.isWebSocket()) {
			parseWebSocketResponse(session, rxBuffer);
			return;
		}
		if (session.isHttp2()) {
			parseHttp2Response(session, rxBuffer);
			return;
		}

		HttpResponseImpl response = session.getResponse();

		response.putBinary(data);
		response.addPutLength(data.readableBytes());

		/* multiple responses in a session. */
		if (session.getResponseState() == HttpResponseState.END) {
			session.setResponseState(HttpResponseState.READY);
		}

		while (session.getResponseState() != HttpResponseState.END) {
			log.debug("parseResponse state={}, sessionKey={}, rxBuffer.readableBytes={}B", session.getResponseState(), session.getKey(), rxBuffer.readableBytes());
			switch (session.getResponseState()) {
				case READY:
				case GOT_HTTP_VER: {
					try {
						int len = rxBuffer.bytesBefore(new byte[]{0x20});
						if (len == 0) {
							log.debug("parseResponse length is zero");
							return;
						}

						byte[] bytes = new byte[len];
						rxBuffer.gets(bytes);

						rxBuffer.get();

						if (session.getResponseState() == HttpResponseState.READY) {
							String httpVersion = new String(bytes);
							if (!httpVersion.startsWith("HTTP/")) {
								rxBuffer.reset();
								if (log.isDebugEnabled()) {
									log.debug("parseResponse httpVersion={}, hex={}", httpVersion, HexFormatter.encodeHexString(httpVersion.getBytes(StandardCharsets.UTF_8)));
								}
								return;
							}
							response.setHttpVersion(httpVersion);
							session.setResponseState(HttpResponseState.GOT_HTTP_VER);
						} else {
							try {
								String statusStr = new String(bytes);
								int statusCode = Integer.parseInt(statusStr);
								response.setStatusCode(statusCode);
								session.setResponseState(HttpResponseState.GOT_STATUS_CODE);
							} catch (NumberFormatException e) {
								throw new IllegalStateException("sessionKey=" + session.getKey() + ", data=" + HexFormatter.encodeHexString(bytes), e);
							}
						}
					} catch (BufferUnderflowException e) {
						rxBuffer.reset();
						log.debug("parseResponse", e);
						return;
					}
					break;
				}
				case GOT_STATUS_CODE: {
					try {
						int len = rxBuffer.bytesBefore(new byte[]{0x0d}); // test 0xa

						byte[] t = new byte[len];
						rxBuffer.gets(t);

						rxBuffer.get(); // 0xd

						rxBuffer.mark();
						if (rxBuffer.get() != 0xa) {
							rxBuffer.reset();
						}

						response.setReasonPhrase(new String(t));
						session.setResponseState(HttpResponseState.GOT_REASON_PHRASE);
					} catch (BufferUnderflowException e) {
						rxBuffer.reset();
						return;
					}
					break;
				}
				case GOT_REASON_PHRASE: {
					try {
						int len = rxBuffer.bytesBefore(new byte[]{0x0d}); // test 0xa
						if (len == 0) {
							return;
						}

						byte[] t = new byte[len];
						rxBuffer.gets(t);

						rxBuffer.get(); // 0xd

						rxBuffer.mark();
						if (rxBuffer.get() != 0xa) {
							rxBuffer.reset();
						}

						String header = new String(t);
						if (log.isDebugEnabled()) {
							log.debug("Parse http response header: {}", header);
						}
						response.addHeader(header);

						rxBuffer.mark();
						byte d = rxBuffer.get();
						byte a = rxBuffer.get();
						if (d == 0x0d && a == 0x0a) {
							session.setResponseState(HttpResponseState.GOT_HEADER);
						} else {
							rxBuffer.reset();
						}
					} catch (BufferUnderflowException e) {
						rxBuffer.reset();
						return;
					}
					break;
				}
				case GOT_HEADER: {
					/* Get body of response */
					EnumSet<FlagEnum> flag = response.getFlags();

					/* Classify response type */
					if ((flag.size() <= 1) && (flag.contains(FlagEnum.NONE))) {
						rxBuffer.mark();
						setResponseType(response);
					}
					if (log.isDebugEnabled()) {
						log.debug("parseResponse state={}, flag={}, sessionKey={}", new Object[]{session.getResponseState(), flag, session.getKey()});
					}

					if (flag.contains(FlagEnum.NORMAL)) {
						if (handleNormal(response, rxBuffer) == DECODE_NOT_READY) {
							rxBuffer.reset();
							return;
						} else {
							decodeContent(response);
						}
					} else {
						/* step 1. handle MULTIPART or BYTERANGE */
						if (flag.contains(FlagEnum.MULTIPART)) {
							handleMultipart(response, rxBuffer);
						} else if (flag.contains(FlagEnum.BYTERANGE)) {
							String url = session.getRequest().getURL().toString();
							if (handleByteRange(session, response, url, rxBuffer, data, capacity) == DECODE_NOT_READY) {
								return;
							}
						}

						/* step 2 */
						if (flag.contains(FlagEnum.CHUNKED)) {
							int retVal = handleChunked(response, rxBuffer, session, session.getRequest(), response);
							if (log.isDebugEnabled()) {
								log.debug("handleChunked ret={}, trunkLength={}", retVal, response.getChunkedLength());
							}

							if (retVal == DECODE_NOT_READY) {
								rxBuffer.reset();
								return;
							} else if (retVal == 0) {
								return;
							} else {
								if (log.isDebugEnabled()) {
									log.debug("parseResponse state={}, flag={}", session.getResponseState(), flag);
								}
								response.setChunked(response.readChunkedBytes());
							}
						}

						/* step 3 */
						if (flag.contains(FlagEnum.DEFLATE)) {
							int retVal = handleDeflate(response, rxBuffer);
							if (retVal == DECODE_NOT_READY) {
								return;
							}
						} else if (flag.contains(FlagEnum.GZIP)) {
							int retVal;
							if (flag.contains(FlagEnum.CHUNKED)) {
								response.putGzip(response.getChunked());
								retVal = 0;
							} else {
								retVal = handleGzip(response, rxBuffer);
							}

							if (retVal == DECODE_NOT_READY || retVal == 1) {
								return;
							} else if (retVal == 0) {
								byte[] decompressed = decompressGzip(response.getGzip());
								response.setDecompressedGzip(decompressed);
							}
						}
					}

					dispatchResponse(session);
					session.setResponseState(HttpResponseState.END);
					HttpRequestImpl request = session.getRequest();
					if (request.isWebSocket() && response.isWebSocket()) {
						session.setWebSocket();

						for (HttpProcessor processor : callbacks) {
							processor.onWebSocketHandshake(session, request, response);
						}
					} else {
						session.removeHttpMessages();
					}
					break;
				}
				default:
					log.warn("parseResponse state={}, sessionKey={}", session.getResponseState(), session.getKey());
					break;
			}
		}
	}

	private void setRequestType(HttpRequestImpl request) {
		log.debug("setRequestType headers={}", request.headers);
		EnumSet<FlagEnum> flags = request.getFlags();

		String contentRange = request.getHeader(HttpHeaders.CONTENT_RANGE);
		if (contentRange != null) {
			if (contentRange.toLowerCase().startsWith("bytes")) {
				flags.add(FlagEnum.BYTERANGE);
				return;
			}
		}

		String contentType = request.getHeader(HttpHeaders.CONTENT_TYPE);
		if (contentType != null) {
			if (contentType.toLowerCase().startsWith("multipart/byteranges")) {
				flags.add(FlagEnum.BYTERANGE);
				return;
			} else if (contentType.toLowerCase().startsWith("multipart")) {
				flags.add(FlagEnum.MULTIPART);
				return;
			}
		}

		String transferEncoding = request.getHeader(HttpHeaders.TRANSFER_ENCODING);
		if (transferEncoding != null) {
			if (transferEncoding.toLowerCase().startsWith("chunked")) {
				flags.add(FlagEnum.CHUNKED);
				request.createChunked();
			}
		}

		String contentEncoding = request.getHeader(HttpHeaders.CONTENT_ENCODING);
		if (contentEncoding != null) {
			if (contentEncoding.toLowerCase().startsWith("gzip")) {
				flags.add(FlagEnum.GZIP);
				return;
			}
		}

		if ((flags.size() <= 1) && (flags.contains(FlagEnum.NONE))) {
			flags.add(FlagEnum.NORMAL);
		}
	}

	private void setResponseType(HttpResponseImpl response) {
		EnumSet<FlagEnum> flags = response.getFlags();

		String contentRange = response.getHeader(HttpHeaders.CONTENT_RANGE);
		if (contentRange != null) {
			if (contentRange.startsWith("bytes")) {
				flags.add(FlagEnum.BYTERANGE);
				return;
			}
		}

		String contentType = response.getHeader(HttpHeaders.CONTENT_TYPE);
		if (contentType != null) {
			if (contentType.startsWith("multipart/byteranges")) {
				flags.add(FlagEnum.BYTERANGE);
				return;
			} else if (contentType.startsWith("multipart")) {
				flags.add(FlagEnum.MULTIPART);
				return;
			}
		}

		String transferEncoding = response.getHeader(HttpHeaders.TRANSFER_ENCODING);
		if (transferEncoding != null) {
			if (transferEncoding.matches("^chunked")) {
				flags.add(FlagEnum.CHUNKED);
				response.createChunked();
			}
		}

		String contentEncoding = response.getHeader(HttpHeaders.CONTENT_ENCODING);
		if (contentEncoding != null) {
			if (contentEncoding.matches("^gzip")) {
				flags.add(FlagEnum.GZIP);
				response.createGzip();

				String lengthStr = response.getHeader(HttpHeaders.CONTENT_LENGTH);
				if (lengthStr != null)
					response.setGzipLength(Integer.parseInt(lengthStr.trim()));
				return;
			} else if (contentEncoding.matches("^deflate")) {
				flags.add(FlagEnum.DEFLATE);
				return;
			}
		}

		if ((flags.size() <= 1) && (flags.contains(FlagEnum.NONE))) {
			flags.add(FlagEnum.NORMAL);
			response.createContent();
		}
	}

	private void handleMultipart(HttpResponseImpl response, Buffer rxBuffer) {
	}

	private int handleByteRange(HttpSessionImpl session, HttpResponseImpl response, String url, Buffer rxBuffer, Buffer data, int capacity) {
		String type = response.getHeader(HttpHeaders.CONTENT_TYPE);
		if(type == null) {
			return DECODE_NOT_READY;
		}

		if (type.startsWith("multipart/byteranges")) {
			/* case 1: response's Content-Type is multipart/byteranges */
			if (response.getBoundary() == null) {
				int pos = type.indexOf("=");
				response.setBoundary(type.substring(pos + 1).replaceAll("\r", "").replaceAll("\n", ""));
			}

			/* check reach endpoint */
			String endBoundary = "--" + response.getBoundary() + "--\r\n";
			byte[] b = new byte[endBoundary.length()];

			int j = capacity - endBoundary.length();
			data.mark();
			data.position(j);
			for (int i = 0; i < endBoundary.length(); i++) {
				b[i] = data.get();
			}
			data.reset();

			String makeBoundary = new String(b);
			if (endBoundary.equals(makeBoundary)) {
				parseMultipart(session, response, url, rxBuffer);
				return 0;
			}
		}
		/* case 2: response have a Content-Range */
		else {
			int partLength;
			if (response.getPartLength() == DECODE_NOT_READY)
				partLength = getPartLength(response);
			else
				partLength = response.getPartLength();

			int readable = rxBuffer.readableBytes();
			if (readable >= partLength) {
				byte[] t = new byte[readable];
				rxBuffer.gets(t);
				response.setContent(t);
				return 0;
			}
		}
		return DECODE_NOT_READY;
	}

	private int getPartLength(HttpResponseImpl response) {
		String range = response.getHeader(HttpHeaders.CONTENT_RANGE);
		if (range == null)
			return DECODE_NOT_READY;

		int pos = range.indexOf("bytes ");
		String[] ranges = range.substring(pos + 6).split("/")[0].split("-");
		int begin = Integer.parseInt(ranges[0]);
		int end = Integer.parseInt(ranges[1]);

		response.setPartLength(end - begin);
		return (end - begin);
	}

	private void parseMultipart(HttpSessionImpl session, HttpResponseImpl response, String url, Buffer rxBuffer) {
		byte[] boundary = response.getBoundary().getBytes();

		try {
			byte b;
			while (true) {
				b = rxBuffer.get();
				/* find boundary */
				if (!(b == 0x2d && rxBuffer.get() == 0x2d))
					continue;

				rxBuffer.mark();
				int k;
				for (k = 0; k < boundary.length; k++) {
					b = rxBuffer.get();

					if (b != boundary[k]) {
						rxBuffer.reset();
						break;
					}
				}
				if (k != boundary.length) {
					continue;
				}

				/* skip \r\n */
				rxBuffer.get();
				rxBuffer.get();

				boolean isGetRange = false;
				while (!isGetRange) {
					/* read bytes after boundary */
					int headerLen = 0;
					rxBuffer.mark();

					while (true) {
						b = rxBuffer.get();
						if (b == 0x3a || b == DECODE_NOT_READY)
							break;
						headerLen++;
					}

					rxBuffer.reset();
					byte[] hBytes = new byte[headerLen];
					rxBuffer.gets(hBytes);

					String header = new String(hBytes);
					if (header.equalsIgnoreCase("Content-Range")) {
						int l = 0;
						while (l < 8) {
							/* skip ': bytes ' */
							rxBuffer.get();
							l++;
						}

						List<Byte> bList = new ArrayList<>();
						while (true) {
							b = rxBuffer.get();
							if (b == 0x0d)
								break;
							bList.add(b);
						}

						/* skip \r\n\r\n */
						rxBuffer.get();
						rxBuffer.get();
						rxBuffer.get();

						byte[] rangeBytes = new byte[bList.size()];
						for (int i = 0; i < rangeBytes.length; i++) {
							rangeBytes[i] = bList.get(i);
						}

						String range = new String(rangeBytes);
						String[] token = range.split("/");

						if (token.length <= 1) {
							isGetRange = true;
							continue;
						}

						String[] s = token[0].split("-");

						int first = Integer.parseInt(s[0]);
						int last = Integer.parseInt(s[1]);
						int length = last - first;
						int readOffset = 0;

						byte[] data = new byte[length];

						while (readOffset < length) {
							data[readOffset] = rxBuffer.get();
							readOffset++;
						}
						mpManager.handleMultipartData(session, this, first, last, token[1], url, data);
						isGetRange = true;
					} else {
						do {
							b = rxBuffer.get();
						} while (b != 0x0a);
					}
				}
			}
		} catch (BufferUnderflowException e) {
			rxBuffer.reset();
		}

	}

	private int handleGzip(HttpResponseImpl response, Buffer rxBuffer) {
		String s = response.getHeader(HttpHeaders.CONTENT_LENGTH);

		if (s == null)
			return response.getStatusCode() == 200 ? DECODE_NOT_READY : 0;

		int length = response.getGzipLength();
		int offset = response.getGzipOffset();
		if (length > DECODE_NOT_READY) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try {
				while (offset < length) {
					baos.write(rxBuffer.get());
					offset++;
				}
			} catch (BufferUnderflowException e) {
				response.setGzipOffset(offset);
				return DECODE_NOT_READY;
			} finally {
				Buffer gzip = response.getGzip();
				gzip.addLast(baos.toByteArray());
			}
			return 0;
		}
		/* can't handle gzip */
		else
			return 1;
	}

	private int handleDeflate(HttpResponseImpl response, Buffer rxBuffer) throws IOException {
        /* save response contents until offset is equal to contentLength */
        String s = response.getHeader(HttpHeaders.CONTENT_LENGTH);
        // log.debug("handleNormal contentLength=" + s + ", available=" + rxBuffer.readableBytes() + ", headerKeys=" + response.getHeaderKeys());

        // if status is OK, receive all bytes until session is finished
        // TODO: other error codes(ex. 304) may have contents body
        if (s == null) {
            return response.getStatusCode() == 200 ? DECODE_NOT_READY : 0;
        }

        int contentLength = Integer.parseInt(s.replaceAll("\\n", ""));

        /* calculate offset */
        int available = rxBuffer.readableBytes();
        if (available < contentLength) {
            return DECODE_NOT_READY;
        }

        byte[] content = new byte[contentLength];
        rxBuffer.gets(content);
        InputStream in = new InflaterInputStream(new ByteArrayInputStream(content), new Inflater(true));
        response.setDeflatedBytes(toByteArray(in));
        return 0;
	}

	private int handleChunked(Chunked chunked, Buffer buffer, HttpSession session, HttpRequest req, HttpResponse resp) {
		/*
		 * return -1: can't get chunked length; return 0: size of chunked > chunked size of rxBuffer; return 1: flush chunked
		 */

		int retVal;

		while (true) {
			if (chunked.getChunkedLength() == DECODE_NOT_READY) {
				if (buffer.isEOB()) {
					return 0;
				}
				buffer.mark();
				buffer.discardReadBytes();

				retVal = getChunkedLength(buffer, chunked);
				/* failed get chunked length */
				if (retVal == DECODE_NOT_READY) {
					return DECODE_NOT_READY;
				}
				/* arrived EOF */
				else if (chunked.getChunkedLength() == 0) {
					/* skip \r\n */
					buffer.get();
					buffer.get();
					break;
				}
				/* succeed get chunked length */
				else {
					if (processChunked(chunked, buffer, session, req, resp)) {
						return 0;
					}
				}
			} else {
				/* already response have chunked length */
				if (processChunked(chunked, buffer, session, req, resp)) {
					return 0;
				}
			}
		}
		return 1;
	}

	private boolean processChunked(Chunked chunked, Buffer buffer, HttpSession session, HttpRequest req, HttpResponse resp) {
		int offset = chunked.getChunkedOffset();
		int length = chunked.getChunkedLength();
		int retVal = putChunked(buffer, chunked, chunked.getChunkedOffset(), chunked.getChunkedLength());
		if (log.isDebugEnabled()) {
            log.debug("processChunked ret={}, offset={}, length={}", retVal, offset, length);
		}
		if (retVal == DECODE_NOT_READY) {
			return true;
		} else if (retVal == 0) {
			if (resp == null) {
				for (HttpProcessor processor : callbacks) {
					processor.onChunkedRequest(session, req, chunked.getChunked());
				}
			} else {
				for (HttpProcessor processor : callbacks) {
					processor.onChunkedResponse(session, req, resp, chunked.getChunked());
				}
			}
		}
		return false;
	}

	private int handleNormal(HttpResponseImpl response, Buffer rxBuffer) {
		/* save response contents until offset is equal to contentLength */
		String s = response.getHeader(HttpHeaders.CONTENT_LENGTH);
		// log.debug("handleNormal contentLength=" + s + ", available=" + rxBuffer.readableBytes() + ", headerKeys=" + response.getHeaderKeys());
		if (s == null) {
			for (String key : response.getHeaderKeys()) {
				if (HttpHeaders.CONTENT_LENGTH.equalsIgnoreCase(key)) {
					s = response.getHeader(key);
					break;
				}
			}
		}

		// if status is OK, receive all bytes until session is finished
		// TODO: other error codes(ex. 304) may have contents body
		if (s == null) {
			return response.getStatusCode() == 200 ? DECODE_NOT_READY : 0;
		}

		int contentLength = Integer.parseInt(s.replaceAll("\\n", ""));

		/* calculate offset */
		int available = rxBuffer.readableBytes();
		if (available < contentLength) {
			return DECODE_NOT_READY;
		}

		byte[] content = new byte[contentLength];
		rxBuffer.gets(content);
		response.getContentBuffer().addLast(content);
		return 0;
	}

	private void decodeContent(HttpResponseImpl response) {
        /*try {
			Buffer binary = response.getBinary();
			int length = response.getPutLength();
			byte[] b = new byte[length];
			binary.gets(b, 0, length);

			Session session = Session.getDefaultInstance(new Properties());
			InputStream is = new ByteArrayInputStream(b, 0, b.length);
			MimeMessage msg = new MimeMessage(session, is);
			response.setMessage(msg);

			if (msg.getContent() instanceof String) {
				Buffer contentBuffer = response.getContentBuffer();
				if(contentBuffer == null) {
					return;
				}
				
				int readable = contentBuffer.readableBytes();
				if (readable <= 0)
					return;

				byte[] content = new byte[readable];
				contentBuffer.gets(content);
				response.setContent(content);
			}
		} catch (Exception e) {
			if (logger.isDebugEnabled())
				logger.debug("kraken http decoder: cannot decode content", e);
		}*/
	}

    public static byte[] toByteArray(InputStream inputStream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int read;
        while ((read = inputStream.read(buf)) != -1) {
            baos.write(buf, 0, read);
        }
        return baos.toByteArray();
    }

	private byte[] decompressGzip(Buffer gzipContent) throws DataFormatException {
		byte[] gzip = new byte[gzipContent.readableBytes()];
		gzipContent.gets(gzip);
		try {
			GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(gzip));
			Buffer gzBuffer = new ChainBuffer();

			/* read fixed length(1000 bytes) from gzip contents */
			byte[] newGzip = new byte[1024];
			int readLen = gzis.read(newGzip);
			int sumOfReadLen = 0;

			if (readLen == DECODE_NOT_READY) {
				throw new DataFormatException();
			}

			while (readLen != DECODE_NOT_READY) {
				byte[] payload = Arrays.copyOf(newGzip, readLen);
				gzBuffer.addLast(payload);
				newGzip = new byte[1000];
				sumOfReadLen += readLen;
				readLen = gzis.read(newGzip);
			}

			byte[] decompressedGzip = new byte[sumOfReadLen];
			gzBuffer.gets(decompressedGzip);
			return decompressedGzip;
		} catch (IOException e) {
			StringWriter writer = new StringWriter();
			new Exception("decompressGzip: " + HexFormatter.encodeHexString(gzip), e).printStackTrace(new PrintWriter(writer));
			return writer.toString().getBytes(StandardCharsets.UTF_8);
		}
	}

	private int getChunkedLength(Buffer rxBuffer, Chunked chunked) {
		try {
			int length = rxBuffer.bytesBefore(new byte[] { 0x0d, 0x0a });
			if (length == 0) {
				chunked.setChunkedLength(DECODE_NOT_READY);
				return DECODE_NOT_READY;
			}
			if (length > 0x16) {
				byte[] bytes = new byte[rxBuffer.readableBytes()];
				rxBuffer.gets(bytes);
				throw new IllegalStateException("getChunkedLength failed: bytes=" + HexFormatter.encodeHexString(bytes));
			}
			String chunkLength = rxBuffer.getString(length).trim();
			int len = Integer.parseInt(chunkLength, 16);
			chunked.setChunkedLength(len);

			/* skip \r\n */
			rxBuffer.get();
			rxBuffer.get();
			return 0;
		} catch (BufferUnderflowException e) {
			log.warn("getChunkedLength", e);
			chunked.setChunkedLength(DECODE_NOT_READY);
			return DECODE_NOT_READY;
		}
	}

	private int putChunked(Buffer buffer, Chunked chunked, int offset, int length) {
        if (buffer.readableBytes() < length - offset + 2) {
            return DECODE_NOT_READY;
        }

		ByteArrayOutputStream baos = new ByteArrayOutputStream(length - offset);
		try {
			while (offset < length) {
				baos.write(buffer.get());
				offset++;
			}
			buffer.get();
			buffer.get();
			/* when read chunked complete, initialize chunked variables */
			chunked.setChunkedOffset(0);
			chunked.setChunkedLength(DECODE_NOT_READY);
		} catch (BufferUnderflowException e) {
			log.warn("putChunked", e);
			chunked.setChunkedOffset(offset);
			return DECODE_NOT_READY;
		} finally {
			chunked.getChunked().addLast(baos.toByteArray());
		}
		return 0;
	}

	private void dispatchRequest(HttpSessionImpl session, HttpRequestImpl request) {
		if (log.isDebugEnabled()) {
            log.debug("dispatchRequest session={}, callbacks={}", session.getKey(), callbacks);
		}
		for (HttpProcessor processor : callbacks) {
			processor.onRequest(session, request);
		}
	}

	private void dispatchResponse(HttpSessionImpl session) throws IOException {
		if (log.isDebugEnabled()) {
            log.debug("dispatchResponse session={}", session);
		}
		session.getResponse().setContent();

		for (HttpProcessor processor : callbacks) {
			processor.onResponse(session, session.getRequest(), session.getResponse());
		}
	}

	public void dispatchMultipartData(HttpSessionImpl session, byte[] data, int offset, int length) {
		Buffer bb = new ChainBuffer(Arrays.copyOfRange(data, offset, length));

		for (HttpProcessor processor : callbacks) {
			processor.onMultipartData(session, bb);
		}
	}
}
