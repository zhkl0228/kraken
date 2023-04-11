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
import org.krakenapps.pcap.decoder.http.h2.HttpField;
import org.krakenapps.pcap.decoder.http.h2.HttpHeader;
import org.krakenapps.pcap.decoder.http.h2.HttpMethod;
import org.krakenapps.pcap.decoder.http.h2.HttpScheme;
import org.krakenapps.pcap.decoder.http.h2.StaticTableHttpField;
import org.krakenapps.pcap.decoder.http.h2.entry.Entry;
import org.krakenapps.pcap.decoder.http.h2.entry.StaticEntry;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.decoder.tcp.TcpState;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author mindori
 */
public class HttpSessionImpl implements HttpSession {

	private static final Logger LOG = LoggerFactory.getLogger(HttpSessionImpl.class);

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

	public boolean txClosed, rxClosed;

	public boolean isAllClosed() {
		return txClosed && rxClosed;
	}

	private boolean isHttp2;
	private int _maxDynamicTableSizeInBytes;

	public boolean isHttp2() {
		return isHttp2;
	}

	public void setHttp2(int maxDynamicTableSize) {
		isHttp2 = true;
		_maxDynamicTableSizeInBytes=maxDynamicTableSize;
		int guesstimateEntries = 10+maxDynamicTableSize/(32+10+10);
		_dynamicTable = new DynamicTable(guesstimateEntries);
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

	private int _dynamicTableSizeInBytes;
	private DynamicTable _dynamicTable;
	private final Map<String,Entry> _nameMap = new HashMap<String,Entry>();

	public Entry get(int index) {
		if (index<=STATIC_SIZE)
			return __staticTable[index];

		return _dynamicTable.get(index);
	}

	public void resize(int newMaxDynamicTableSize)
	{
		if (LOG.isDebugEnabled())
			LOG.debug(String.format("HdrTbl[%x] resized max=%d->%d",hashCode(),_maxDynamicTableSizeInBytes,newMaxDynamicTableSize));
		_maxDynamicTableSizeInBytes=newMaxDynamicTableSize;
		_dynamicTable.evict();
	}

	public Entry add(HttpField field)
	{
		Entry entry=new Entry(field);
		int size = entry.getSize();
		if (size>_maxDynamicTableSizeInBytes)
		{
			if (LOG.isDebugEnabled())
				LOG.debug(String.format("HdrTbl[%x] !added size %d>%d",hashCode(),size,_maxDynamicTableSizeInBytes));
			return null;
		}
		_dynamicTableSizeInBytes+=size;
		_dynamicTable.add(entry);
		_nameMap.put(HttpField.asciiToLowerCase(field.getName()),entry);

		if (LOG.isDebugEnabled())
			LOG.debug(String.format("HdrTbl[%x] added %s",hashCode(),entry));
		_dynamicTable.evict();
		return entry;
	}

	private class DynamicTable {
		Entry[] _entries;
		int _size;
		int _offset;
		int _growby;

		private DynamicTable(int initCapacity) {
			_entries=new Entry[initCapacity];
			_growby=initCapacity;
		}

		public void add(Entry entry) {
			if (_size==_entries.length) {
				Entry[] entries = new Entry[_entries.length+_growby];
				for (int i=0;i<_size;i++) {
					int slot = (_offset+i)%_entries.length;
					entries[i]=_entries[slot];
					entries[i]._slot=i;
				}
				_entries=entries;
				_offset=0;
			}
			int slot=(_size++ + _offset)%_entries.length;
			_entries[slot]=entry;
			entry._slot=slot;
		}

		public int index(Entry entry) {
			return STATIC_SIZE + _size-(entry._slot-_offset+_entries.length)%_entries.length;
		}

		public Entry get(int index) {
			int d = index-STATIC_SIZE-1;
			if (d<0 || d>=_size)
				return null;
			int slot = (_offset+_size-d-1)%_entries.length;
			return _entries[slot];
		}

		public int size() {
			return _size;
		}

		private void evict() {
			while (_dynamicTableSizeInBytes>_maxDynamicTableSizeInBytes) {
				Entry entry = _entries[_offset];
				_entries[_offset]=null;
				_offset = (_offset+1)%_entries.length;
				_size--;
				if (LOG.isDebugEnabled())
					LOG.debug(String.format("HdrTbl[%x] evict %s",this.hashCode(),entry));
				_dynamicTableSizeInBytes-=entry.getSize();
				entry._slot=-1;
				String lc= HttpField.asciiToLowerCase(entry.getHttpField().getName());
				if (entry==_nameMap.get(lc))
					_nameMap.remove(lc);

			}
			if (LOG.isDebugEnabled())
				LOG.debug(String.format("HdrTbl[%x] entries=%d, size=%d, max=%d",this.hashCode(),_dynamicTable.size(),_dynamicTableSizeInBytes,_maxDynamicTableSizeInBytes));
		}

	}

	private static final String EMPTY = "";
	public static final String[][] STATIC_TABLE =
			{
					{null,null},
					/* 1  */ {":authority",EMPTY},
					/* 2  */ {":method","GET"},
					/* 3  */ {":method","POST"},
					/* 4  */ {":path","/"},
					/* 5  */ {":path","/index.html"},
					/* 6  */ {":scheme","http"},
					/* 7  */ {":scheme","https"},
					/* 8  */ {":status","200"},
					/* 9  */ {":status","204"},
					/* 10 */ {":status","206"},
					/* 11 */ {":status","304"},
					/* 12 */ {":status","400"},
					/* 13 */ {":status","404"},
					/* 14 */ {":status","500"},
					/* 15 */ {"accept-charset",EMPTY},
					/* 16 */ {"accept-encoding","gzip, deflate"},
					/* 17 */ {"accept-language",EMPTY},
					/* 18 */ {"accept-ranges",EMPTY},
					/* 19 */ {"accept",EMPTY},
					/* 20 */ {"access-control-allow-origin",EMPTY},
					/* 21 */ {"age",EMPTY},
					/* 22 */ {"allow",EMPTY},
					/* 23 */ {"authorization",EMPTY},
					/* 24 */ {"cache-control",EMPTY},
					/* 25 */ {"content-disposition",EMPTY},
					/* 26 */ {"content-encoding",EMPTY},
					/* 27 */ {"content-language",EMPTY},
					/* 28 */ {"content-length",EMPTY},
					/* 29 */ {"content-location",EMPTY},
					/* 30 */ {"content-range",EMPTY},
					/* 31 */ {"content-type",EMPTY},
					/* 32 */ {"cookie",EMPTY},
					/* 33 */ {"date",EMPTY},
					/* 34 */ {"etag",EMPTY},
					/* 35 */ {"expect",EMPTY},
					/* 36 */ {"expires",EMPTY},
					/* 37 */ {"from",EMPTY},
					/* 38 */ {"host",EMPTY},
					/* 39 */ {"if-match",EMPTY},
					/* 40 */ {"if-modified-since",EMPTY},
					/* 41 */ {"if-none-match",EMPTY},
					/* 42 */ {"if-range",EMPTY},
					/* 43 */ {"if-unmodified-since",EMPTY},
					/* 44 */ {"last-modified",EMPTY},
					/* 45 */ {"link",EMPTY},
					/* 46 */ {"location",EMPTY},
					/* 47 */ {"max-forwards",EMPTY},
					/* 48 */ {"proxy-authenticate",EMPTY},
					/* 49 */ {"proxy-authorization",EMPTY},
					/* 50 */ {"range",EMPTY},
					/* 51 */ {"referer",EMPTY},
					/* 52 */ {"refresh",EMPTY},
					/* 53 */ {"retry-after",EMPTY},
					/* 54 */ {"server",EMPTY},
					/* 55 */ {"set-cookie",EMPTY},
					/* 56 */ {"strict-transport-security",EMPTY},
					/* 57 */ {"transfer-encoding",EMPTY},
					/* 58 */ {"user-agent",EMPTY},
					/* 59 */ {"vary",EMPTY},
					/* 60 */ {"via",EMPTY},
					/* 61 */ {"www-authenticate",EMPTY},
			};
	public static final int STATIC_SIZE = STATIC_TABLE.length-1;
	private static final StaticEntry[] __staticTable=new StaticEntry[STATIC_TABLE.length];
	static
	{
		for (int i=1;i<STATIC_TABLE.length;i++)
		{
			StaticEntry entry=null;

			String name  = STATIC_TABLE[i][0];
			String value = STATIC_TABLE[i][1];
			HttpHeader header = HttpHeader.CACHE.get(name);
			if (header!=null && value!=null)
			{
				switch (header)
				{
					case C_METHOD:
					{

						HttpMethod method = HttpMethod.CACHE.get(value);
						if (method!=null)
							entry=new StaticEntry(i,new StaticTableHttpField(header,name,value,method));
						break;
					}

					case C_SCHEME:
					{

						HttpScheme scheme = HttpScheme.CACHE.get(value);
						if (scheme!=null)
							entry=new StaticEntry(i,new StaticTableHttpField(header,name,value,scheme));
						break;
					}

					case C_STATUS:
					{
						entry=new StaticEntry(i,new StaticTableHttpField(header,name,value,Integer.valueOf(value)));
						break;
					}

					default:
						break;
				}
			}

			if (entry==null)
				entry=new StaticEntry(i,header==null?new HttpField(STATIC_TABLE[i][0],value):new HttpField(header,name,value));


			__staticTable[i]=entry;
		}
	}
}
