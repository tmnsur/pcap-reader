package info.tmnsur.pcap;

public class PacketHeader {
	private int epochSeconds;
	private int offset;
	private int actualLength;
	private int originalLength;

	public int getActualLength() {
		return actualLength;
	}

	public void setActualLength(int actualLength) {
		this.actualLength = actualLength;
	}

	public int getEpochSeconds() {
		return epochSeconds;
	}

	public void setEpochSeconds(int epochSeconds) {
		this.epochSeconds = epochSeconds;
	}

	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

	public int getOriginalLength() {
		return originalLength;
	}

	public void setOriginalLength(int originalLength) {
		this.originalLength = originalLength;
	}
}
