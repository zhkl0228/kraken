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
package org.krakenapps.pcap.decoder.tcp;

import java.net.InetSocketAddress;
import java.util.Collection;

import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.util.Buffer;

public interface TcpProtocolMapper extends ProtocolDetector {
	Protocol map(TcpSegment segment);

	Collection<TcpProcessor> getTcpProcessors(Protocol protocol);

	void register(Protocol protocol, TcpProcessor processor);

	void unregister(Protocol protocol, TcpProcessor processor);

	boolean containsProtocol(InetSocketAddress sockAddr);

	void register(InetSocketAddress server, Protocol protocol);

	void unregister(InetSocketAddress server);

	@Deprecated
	TcpProcessor getTcpProcessor(Protocol protocol);

	@Deprecated
	void unregister(Protocol protocol);
	
	void setUnknownProtocolProcessor(TcpProcessor processor);

}
