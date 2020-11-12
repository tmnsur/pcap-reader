package info.tmnsur.pcap;

public class Packet {
	private PacketHeader header;
	private byte[] data;

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public PacketHeader getHeader() {
		return header;
	}

	public void setHeader(PacketHeader header) {
		this.header = header;
	}
}
