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
package org.krakenapps.pcap.file;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.krakenapps.pcap.PcapOutputStream;
import org.krakenapps.pcap.packet.PacketHeader;
import org.krakenapps.pcap.packet.PcapPacket;
import org.krakenapps.pcap.util.Buffer;

/**
 * PcapFileOutputStream writes pcap packet stream to pcap file.
 * 
 * http://wiki.wireshark.org/Development/LibpcapFileFormat
 * @author mindori
 * @since 1.1
 */
public class PcapFileOutputStream implements PcapOutputStream {

	private FileOutputStream fos;
	
	private final int datalink;

	public PcapFileOutputStream(File file, int datalink) throws IOException {
		super();
		this.datalink = datalink;

		if (file.exists()) {
			throw new IOException("file exists: " + file.getName());
		}
		fos = new FileOutputStream(file);
		createGlobalHeader();
	}

	public PcapFileOutputStream(File file, GlobalHeader header) throws IOException {
		super();
		this.datalink = header.getNetwork();

		if (file.exists()) {
			fos = new FileOutputStream(file, true);
		} else {
			fos = new FileOutputStream(file);
			copyGlobalHeader(header);
		}
	}

	private synchronized void createGlobalHeader() throws IOException {
		/* magic number(swapped) */
		fos.write(new byte[] { (byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1 });

		/* major version number */
		fos.write(new byte[] { 0x2, 0x0 });

		/* minor version number */
		fos.write(new byte[] { 0x4, 0x0 });

		/* GMT to local correction */
		fos.write(new byte[4]);

		/* accuracy of timestamps */
		fos.write(new byte[4]);

		/* max length of captured packets, in octets */
		fos.write(new byte[] { (byte) 0xff, (byte) 0xff, 0x0, 0x0 });

		/* data link type(ethernet) */
		byte[] g = intToByteArrayLE(datalink);
		fos.write(g);
	}
	
	private synchronized void copyGlobalHeader(GlobalHeader header) throws IOException {
		byte[] a = intToByteArray(header.getMagicNumber());
		byte[] b = shortToByteArrayLE(header.getMajorVersion());
		byte[] c = shortToByteArrayLE(header.getMinorVersion());
		byte[] d = intToByteArrayLE(header.getThiszone());
		byte[] e = intToByteArrayLE(header.getSigfigs());
		byte[] f = intToByteArrayLE(header.getSnaplen());
		byte[] g = intToByteArrayLE(header.getNetwork());

		fos.write(a);
		
		fos.write(b);
		
		fos.write(c);
		
		fos.write(d);
		
		fos.write(e);
		
		fos.write(f);
		
		fos.write(g);
	}
	
	public synchronized void write(PcapPacket packet) throws IOException {
		PacketHeader packetHeader = packet.getPacketHeader();

		int tsSec = packetHeader.getTsSec();
		int tsUsec = packetHeader.getTsUsec();
		int inclLen = packetHeader.getInclLen();
		int origLen = packetHeader.getOrigLen();

		addInt(tsSec);
		addInt(tsUsec);
		addInt(inclLen);
		addInt(origLen);

		Buffer payload = packet.getPacketData();

		try {
			payload.mark();
			byte[] buf = new byte[payload.readableBytes()];
			payload.gets(buf);
			fos.write(buf);
		} finally {
			payload.reset();
		}

		flush();
	}

	private synchronized void addInt(int d) throws IOException {
		fos.write(intToByteArrayLE(d));
	}

	private static byte[] intToByteArray(int d) {
		return new byte[] { (byte) (d >>> 24), (byte) (d >>> 16), (byte) (d >>> 8), (byte) d };
	}

	private static byte[] intToByteArrayLE(int d) {
		return new byte[] { (byte) d, (byte) (d >>> 8), (byte) (d >>> 16), (byte) (d >>> 24) };
	}

	private static byte[] shortToByteArray(short s) {
		return new byte[] { (byte) (s >>> 8), (byte) s };
	}

	private static byte[] shortToByteArrayLE(short s) {
		return new byte[] { (byte) s, (byte) (s >>> 8) };
	}

	@Override
	public synchronized void flush() throws IOException {
		fos.flush();
	}

	@Override
	public synchronized void close() throws IOException {
		flush();
		fos.close();
	}
}
