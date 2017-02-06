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

import java.net.Inet4Address;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.Checksum;
import org.krakenapps.pcap.util.IpConverter;

/**
 * @author mindori
 */
public class TcpChecksum {
	
	private TcpChecksum() {
		super();
	}

	public static int sum(TcpPacket s) {
		ByteBuffer buf = build(s);
		
		List<Integer> list = new ArrayList<Integer>((buf.remaining() + 1) / 2);
		
		while(buf.remaining() >= 2) {
			list.add(buf.getShort() & 0xffff);
		}
		if(buf.hasRemaining()) {
			list.add((buf.get() & 0xff) << 8);
		}

		int[] checksumBytes = new int[list.size()];
		for(int i = 0; i < checksumBytes.length; i++) {
			checksumBytes[i] = list.get(i);
		}
		return Checksum.sum(checksumBytes);
	}

	private static ByteBuffer build(TcpPacket s) {
		/* except option and padding: 16 shorts */
		ByteBuffer bb = ByteBuffer.allocate(12 + s.getTotalLength());

		// TODO: IPv6 handling
		// pseudo header
		bb.putInt(IpConverter.toInt((Inet4Address) s.getSourceAddress()));
		bb.putInt(IpConverter.toInt((Inet4Address) s.getDestinationAddress()));
		bb.put((byte) 0); // padding
		bb.put((byte) 6); // tcp
		bb.putShort((short) (s.getTotalLength()));

		bb.putShort((short) s.getSourcePort());
		bb.putShort((short) s.getDestinationPort());
		bb.putInt(s.getSeq());
		bb.putInt(s.getAck());
		bb.put((byte) (s.getDataOffset() << 4));
		bb.put((byte) s.getFlags());
		bb.putShort((short) s.getWindow());
		bb.putShort((short) 0); // checksum
		bb.putShort((short) s.getUrgentPointer());
		if (s.getOptions() != null) {
			bb.put(s.getOptions());
		}
		if (s.getPadding() != null) {
			bb.put(s.getPadding());
		}
		
		Buffer data = s.getData();
		if(data != null) {
			byte[] buf = new byte[data.readableBytes()];
			data.gets(buf);
			bb.put(buf);
			data.rewind();
		}

		bb.flip();
		return bb;
	}

}
