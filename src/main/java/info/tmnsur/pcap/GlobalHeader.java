package info.tmnsur.pcap;

public class GlobalHeader {
	private static final int SWAPPED_MILLI_SECOND_MAGIC_NUMBER = 0xD4C3B2A1;
	private static final int IDENTICAL_NANO_SECOND_MAGIC_NUMBER = 0xA1B23C4D;
	private static final int SWAPPED_NANO_SECOND_MAGIC_NUMBER = 0x4D3CB2A1;

	private int magicNumber;
	private short versionMajor;
	private short versionMinor;
	private int zone;
	private int accuracy;
	private int maxLength;
	private int networkType;

	private boolean swapped;
	private boolean nano;

	public boolean isSwapped() {
		return swapped;
	}

	public boolean isNano() {
		return nano;
	}

	public int getAccuracy() {
		return accuracy;
	}

	public void setAccuracy(int accuracy) {
		this.accuracy = accuracy;
	}

	public int getMagicNumber() {
		return magicNumber;
	}

	public void setMagicNumber(int magicNumber) {
		this.magicNumber = magicNumber;

		this.swapped = SWAPPED_MILLI_SECOND_MAGIC_NUMBER == magicNumber
				|| SWAPPED_NANO_SECOND_MAGIC_NUMBER == magicNumber;
		this.nano = IDENTICAL_NANO_SECOND_MAGIC_NUMBER == magicNumber
				|| SWAPPED_NANO_SECOND_MAGIC_NUMBER == magicNumber;
	}

	public int getMaxLength() {
		return maxLength;
	}

	public void setMaxLength(int maxLength) {
		this.maxLength = maxLength;
	}

	public int getNetworkType() {
		return networkType;
	}

	public void setNetworkType(int networkType) {
		this.networkType = networkType;
	}

	public short getVersionMajor() {
		return versionMajor;
	}

	public void setVersionMajor(short versionMajor) {
		this.versionMajor = versionMajor;
	}

	public short getVersionMinor() {
		return versionMinor;
	}

	public void setVersionMinor(short versionMinor) {
		this.versionMinor = versionMinor;
	}

	public int getZone() {
		return zone;
	}

	public void setZone(int zone) {
		this.zone = zone;
	}
}
