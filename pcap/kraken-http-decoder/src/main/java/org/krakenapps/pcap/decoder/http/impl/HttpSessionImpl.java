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

import com.twitter.hpack.Decoder;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.h2.Http2Stream;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpState;
import org.krakenapps.pcap.util.ChainBuffer;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author mindori
 */
public class HttpSessionImpl implements HttpSession {

	private final TcpSession session;

	private final InetSocketAddress clientAddr;
	private final InetSocketAddress serverAddr;
	private HttpRequestImpl request;
	private HttpResponseImpl response;

	private final Properties props;
	private ChainBuffer txBuffer;
	private ChainBuffer rxBuffer;

	private HttpRequestState requestState;
	private HttpResponseState responseState;

	private boolean isWebSocket;

	public HttpSessionImpl(TcpSession session, InetSocketAddress clientAddr, InetSocketAddress serverAddr) {
		super();

		this.session = session;
		this.clientAddr = clientAddr;
		this.serverAddr = serverAddr;
		props = new Properties();

		txBuffer = new ChainBuffer();
		rxBuffer = new ChainBuffer();

		requestState = HttpRequestState.READY;
		responseState = HttpResponseState.READY;
	}

	public final Map<Integer, Http2Stream> http2StreamMap = new HashMap<>();

	private boolean isHttp2;

	public Decoder txHpackDecoder, rxHpackDecoder;

	public boolean isHttp2() {
		return isHttp2;
	}

	public void setHttp2(int maxHeaderSize, int maxHeaderTableSize) {
		isHttp2 = true;
		txHpackDecoder = new Decoder(maxHeaderSize, maxHeaderTableSize);
		rxHpackDecoder = new Decoder(maxHeaderSize, maxHeaderTableSize);
	}

	public WebSocketFrameImpl txFrame, rxFrame;

	public boolean isWebSocket() {
		return isWebSocket;
	}

	public void setWebSocket() {
		isWebSocket = true;
	}

	@Override
	public HttpRequestImpl getRequest() {
		return request;
	}

	public void createRequest() {
		request = new HttpRequestImpl(clientAddr, serverAddr, getProtocol());
	}

	@Override
	public HttpResponseImpl getResponse() {
		return response;
	}

	public void createResponse() {
		response = new HttpResponseImpl();
	}

	public void removeHttpMessages() {
		request = null;
		response = null;
	}

	public Properties getProps() {
		return props;
	}

	public ChainBuffer getTxBuffer() {
		return txBuffer;
	}

	public void setTxBuffer(ChainBuffer txBuffer) {
		this.txBuffer = txBuffer;
	}

	public ChainBuffer getRxBuffer() {
		return rxBuffer;
	}

	public void setRxBuffer(ChainBuffer rxBuffer) {
		this.rxBuffer = rxBuffer;
	}

	public HttpRequestState getRequestState() {
		return requestState;
	}

	public void setRequestState(HttpRequestState requestState) {
		this.requestState = requestState;
	}

	public HttpResponseState getResponseState() {
		return responseState;
	}

	public void setResponseState(HttpResponseState responseState) {
		this.responseState = responseState;
	}

	public void deallocate() {
		txBuffer = null;
		rxBuffer = null;
	}

	public int getId() {
		return session.getId();
	}

	public TcpState getClientState() {
		return session.getClientState();
	}

	public TcpState getServerState() {
		return session.getServerState();
	}

	public TcpSessionKey getKey() {
		return session.getKey();
	}

	public void registerProtocol(Protocol protocol) {
		session.registerProtocol(protocol);
	}

	public void unregisterProtocol(Protocol protocol) {
		session.unregisterProtocol(protocol);
	}

	public Protocol getProtocol() {
		return session.getProtocol();
	}

	public void setAttribute(String key, Object val) {
		session.setAttribute(key, val);
	}

	public <T> T getAttribute(String key, Class<T> clazz) {
		return session.getAttribute(key, clazz);
	}

	private TcpProcessor fallbackTcpProcessor;

	public void setFallbackTcpProcessor(TcpProcessor fallbackTcpProcessor) {
		this.fallbackTcpProcessor = fallbackTcpProcessor;
	}

	public TcpProcessor getFallbackTcpProcessor() {
		return fallbackTcpProcessor;
	}
}
