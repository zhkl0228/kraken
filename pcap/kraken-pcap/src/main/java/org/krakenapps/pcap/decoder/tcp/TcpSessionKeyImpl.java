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

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * @author mindori
 */
public class TcpSessionKeyImpl implements TcpSessionKey {
	private final InetAddress clientIp;
	private final InetAddress serverIp;
	private final int clientPort;
	private final int serverPort;
	private boolean reversed = false;

	public TcpSessionKeyImpl(InetAddress clientIp, InetAddress serverIp, int clientPort, int serverPort) {
		if (clientIp.hashCode() < serverIp.hashCode()) {
			this.clientIp = clientIp;
			this.serverIp = serverIp;
			this.clientPort = clientPort;
			this.serverPort = serverPort;
		} else {
			this.serverIp = clientIp;
			this.clientIp = serverIp;
			this.serverPort = clientPort;
			this.clientPort = serverPort;
			reversed = true;
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!getClass().isAssignableFrom(obj.getClass()))
			return false;

		TcpSessionKeyImpl o = (TcpSessionKeyImpl) obj;
		if (!clientIp.equals(o.clientIp))
			return false;
		if (clientPort != o.clientPort)
			return false;
		if (!serverIp.equals(o.serverIp))
			return false;
		return serverPort == o.serverPort;
	}

	@Override
	public int hashCode() {
		return clientIp.hashCode() ^ clientPort ^ serverIp.hashCode() ^ serverPort;
	}

	@Override
	public InetAddress getClientIp() {
		return reversed ? serverIp : clientIp;
	}

	@Override
	public InetAddress getServerIp() {
		return reversed ? clientIp : serverIp;
	}

	@Override
	public int getClientPort() {
		return reversed ? serverPort : clientPort;
	}

	@Override
	public int getServerPort() {
		return reversed ? clientPort : serverPort;
	}

	public void flip() {
		reversed = !reversed;
	}

	@Override
	public String toString() {
		return String.format("%s:%d => %s:%d", getClientIp().getHostAddress(), getClientPort(), getServerIp()
				.getHostAddress(), getServerPort());
	}

	@Override
	public InetSocketAddress getServerAddress() {
		return new InetSocketAddress(getServerIp(), getServerPort());
	}

	@Override
	public InetSocketAddress getClientAddress() {
		return new InetSocketAddress(getClientIp(), getClientPort());
	}
}
