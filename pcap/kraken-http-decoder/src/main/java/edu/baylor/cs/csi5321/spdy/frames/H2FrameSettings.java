/**
 * 
 */
package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author zhkl0228
 *
 */
public class H2FrameSettings extends SpdyControlFrame {

	public H2FrameSettings(boolean controlBit, byte flags, int length) throws SpdyException {
		super(controlBit, flags, length);
	}

	@Override
	public SpdyControlFrameType getType() {
		return SpdyControlFrameType.SETTINGS;
	}

	@Override
	public byte[] encode() throws SpdyException {
		throw new UnsupportedOperationException();
	}

	public int getHeaderTableSize() {
		for(SettingEntry entry : entries) {
			if (entry.id == 0x1) {
				return entry.value;
			}
		}
		return 0x10000;
	}

	public int getMaxHeaderListSize() {
		for(SettingEntry entry : entries) {
			if (entry.id == 0x6) {
				return entry.value;
			}
		}
		return 0x40000;
	}

	private static class SettingEntry {
		/**
		 * 0x1 SETTINGS_HEADER_TABLE_SIZE
		 * 0x2 SETTINGS_ENABLE_PUSH
		 * 0x3 SETTINGS_MAX_CONCURRENT_STREAMS
		 * 0x4 SETTINGS_INITIAL_WINDOW_SIZE
		 * 0x5 SETTINGS_MAX_FRAME_SIZE
		 * 0x6 SETTINGS_MAX_HEADER_LIST_SIZE
		 */
		final int id;
		final int value;

		public SettingEntry(int id, int value) {
			super();
			this.id = id;
			this.value = value;
		}

		@Override
		public String toString() {
			return "SettingEntry [id=0x" + Integer.toHexString(id) + ", value=0x" + Integer.toHexString(value) + "]";
		}
	}

	private SettingEntry[] entries = new SettingEntry[0];

	/* (non-Javadoc)
	 * @see edu.baylor.cs.csi5321.spdy.frames.SpdyFrame#decode(java.io.DataInputStream)
	 */
	@Override
	public H2Frame decode(DataInputStream is) throws SpdyException {
		try {
			List<SettingEntry> list = new ArrayList<SettingEntry>();
			while(is.available() > 0) {
				int id = is.readShort() & 0xffff;
				int value = is.readInt();
				list.add(new SettingEntry(id, value));
			}
			this.entries = list.toArray(new SettingEntry[0]);
			return this;
		} catch(IOException e) {
			throw new SpdyException(e);
		}
	}

	@Override
	public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
		List<SettingEntry> list = new ArrayList<SettingEntry>();
		while (buffer.hasRemaining()) {
			int id = buffer.getShort() & 0xffff;
			int value = buffer.getInt();
			list.add(new SettingEntry(id, value));
		}
		this.entries = list.toArray(new SettingEntry[0]);
	}

    @Override
	public String toString() {
		return "H2FrameSettings [entries=" + Arrays.toString(entries) + "]";
	}

}
