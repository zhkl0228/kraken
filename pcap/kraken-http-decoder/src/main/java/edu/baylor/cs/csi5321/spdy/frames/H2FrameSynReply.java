package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameSynReply extends H2FrameStream {

    private H2NameValueBlock nameValueBlock;

    public H2NameValueBlock getNameValueBlock() {
        return nameValueBlock;
    }

    public void setNameValueBlock(H2NameValueBlock nameValueBlock) {
        this.nameValueBlock = nameValueBlock;
    }

    public H2FrameSynReply(H2NameValueBlock nameValueBlock, int streamId, boolean controlBit, byte flags, int length) throws H2Exception {
        super(streamId, controlBit, flags, length);
        this.nameValueBlock = nameValueBlock;
    }

    public H2FrameSynReply(boolean controlBit, byte flags, int length) throws H2Exception {
        super(controlBit, flags, length);
    }

    @Override
    public H2ControlFrameType getType() {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public byte[] encode() throws H2Exception {
        
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(nameValueBlock.encode());
            byte[] body = bout.toByteArray();
            setLength(body.length + 4);  //+4 for streamId
            byte[] header = super.encode();
            return H2Util.concatArrays(header, body);
            
        } catch (IOException ex) {
            throw new H2Exception(ex);
        }
    }

    @Override
    public H2Frame decode(DataInputStream is) throws H2Exception {
        try {
            H2FrameSynReply f = (H2FrameSynReply) super.decode(is);
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
        final H2FrameSynReply other = (H2FrameSynReply) obj;
        return this.nameValueBlock.equals(other.nameValueBlock);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + this.nameValueBlock.hashCode();
        return hash;
    }
    
    
}
