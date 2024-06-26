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

import org.krakenapps.pcap.decoder.http.impl.HttpSession;
import org.krakenapps.pcap.util.Buffer;

/**
 * @author mindori
 */
public interface HttpProcessor extends WebSocketProcessor {
	
	void onRequest(HttpSession session, HttpRequest request);
	
	void onResponse(HttpSession session, HttpRequest request, HttpResponse response);
	
	void onMultipartData(HttpSession session, Buffer buffer);

	void onChunkedRequest(HttpSession session, HttpRequest request, Buffer chunked);
	void onChunkedResponse(HttpSession session, HttpRequest request, HttpResponse response, Buffer chunked);

}
