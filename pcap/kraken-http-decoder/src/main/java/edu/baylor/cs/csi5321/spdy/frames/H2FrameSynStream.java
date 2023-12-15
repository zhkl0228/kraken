package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameSynStream extends H2FrameStream {

    private int associatedToStreamId;
    private byte priority;
    private byte slot;
    private static final int HEADER_LENGTH = 10;
    private H2NameValueBlock nameValueBlock;

    public int getAssociatedToStreamId() {
        return associatedToStreamId;
    }

    public void setAssociatedToStreamId(int associatedToStreamId) throws H2Exception {
        if(associatedToStreamId < 0) {
            throw new H2Exception("StreamId must be 31-bit value in integer, thus it must not be negative value");
        }
        this.associatedToStreamId = associatedToStreamId;
    }

    public byte getPriority() {
        return priority;
    }

    public void setPriority(byte priority) throws H2Exception {
        if(priority < 0) {
            throw new H2Exception("Priority must be between 0 and 7");
        }
        this.priority = priority;
    }

    public byte getSlot() {
        return slot;
    }

    public void setSlot(byte slot) throws H2Exception {
        if(slot != 0) {
            throw new H2Exception("Slot must be 0. Credentials are not supported.");
        }
        this.slot = slot;
    }

    public H2NameValueBlock getNameValueBlock() {
        return nameValueBlock;
    }

    public void setNameValueBlock(H2NameValueBlock nameValueBlock) {
        this.nameValueBlock = nameValueBlock;
    }

    public H2FrameSynStream(int associatedToStreamId, byte priority, byte slot, H2NameValueBlock nameValueBlock, int streamId, short version, boolean controlBit, byte flags, int length) throws H2Exception {
        super(streamId, controlBit, flags, length);
        this.associatedToStreamId = associatedToStreamId;
        setPriority(priority);
        this.slot = slot;
        this.nameValueBlock = nameValueBlock;
    }

    public H2FrameSynStream(int streamId, boolean controlBit, byte flags, int length) throws H2Exception {
        super(controlBit, flags, length);
        this.streamId = streamId;
    }

    public H2FrameSynStream(boolean controlBit, byte flags, int length) throws H2Exception {
        super(controlBit, flags, length);
    }

    @Override
    public byte[] encode() throws H2Exception {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bout);
            out.writeInt(getAssociatedToStreamId() & 0x7FFFFFFF);
            //writing Pri|Unused|Slot
            out.writeByte(getPriority() << 5);
            //we don't use CREDENTIAL, therefore, let's just write 0
            out.writeByte(0);
            out.write(nameValueBlock.encode());
            byte[] body = bout.toByteArray();
            //set the correct length
            setLength(body.length + 4); //+4 for StreamId
            //since we have length, we can generate header
            byte[] header = super.encode();
            //concat header and body
            return H2Util.concatArrays(header, body);
        } catch (IOException ex) {
            throw new H2Exception(ex);
        }
    }

    @Override
    public H2ControlFrameType getType() {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public H2Frame decode(DataInputStream is) throws H2Exception {
        try {
            H2FrameSynStream f = (H2FrameSynStream) super.decode(is);
            int assoc = is.readInt();
            f.setAssociatedToStreamId(assoc & H2Util.MASK_STREAM_ID_HEADER);
            byte priorityAndUnused = is.readByte();
            setPriority((byte) ((priorityAndUnused >> 5) & 0x07));
            byte slot = is.readByte();
            setSlot(slot);
            byte[] pairs = new byte[f.getLength() - HEADER_LENGTH];
            is.readFully(pairs);
            f.setNameValueBlock(H2NameValueBlock.decode(pairs));
            return f;
        } catch (IOException ex) {
            throw new H2Exception(ex);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2FrameSynStream other = (H2FrameSynStream) obj;
        if (this.associatedToStreamId != other.associatedToStreamId) {
            return false;
        }
        if (this.priority != other.priority) {
            return false;
        }
        if (this.slot != other.slot) {
            return false;
        }
        return this.nameValueBlock.equals(other.nameValueBlock);
    }

    @Override
    public int hashCode() {
        int hash = 7 * super.hashCode();
        hash = 83 * hash + this.associatedToStreamId;
        hash = 83 * hash + this.priority;
        hash = 83 * hash + this.slot;
        hash = 83 * hash + this.nameValueBlock.hashCode();
        return hash;
    }
    
    
}
