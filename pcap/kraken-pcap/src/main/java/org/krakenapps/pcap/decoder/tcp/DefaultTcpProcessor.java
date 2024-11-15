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

import org.krakenapps.pcap.util.Buffer;

/**
 * @author mindori
 */
public class DefaultTcpProcessor implements TcpProcessor {

	@Override
	public void handleRx(TcpSessionKey session, Buffer data) {
	}

	@Override
	public void handleTx(TcpSessionKey session, Buffer data) {
	}

	@Override
	public boolean onEstablish(TcpSession session) {
		return false;
	}

	@Override
	public void onFinish(TcpSessionKey key) {
	}

	@Override
	public void onReset(TcpSessionKey key) {
	}

}
