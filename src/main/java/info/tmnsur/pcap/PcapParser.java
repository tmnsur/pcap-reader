package info.tmnsur.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class PcapParser {
	private static short readShort(byte[] data, int start, boolean swapped) {
		if(swapped) {
			return (short) (((data[start + 1] & 0xFF) << 8) | (data[start] & 0xFF));
		}

		return (short) (((data[start] & 0xFF) << 8) | (data[start + 1] & 0xFF));
	}

	private static int readInt(byte[] data, int start, boolean swapped) {
		if(swapped) {
			return ((data[start + 3] & 0xFF) << 24) | ((data[start + 2] & 0xFF) << 16)
					| ((data[start + 1] & 0xFF) << 8) | (data[start] & 0xFF);
		}

		return ((data[start] & 0xFF) << 24) | ((data[start + 1] & 0xFF) << 16) | ((data[start + 2] & 0xFF) << 8)
				| (data[start + 3] & 0xFF);
	}

	private static GlobalHeader parseGlobalHeader(InputStream inputStream) throws IOException {
		byte[] data = new byte[24];

		if(24 != inputStream.read(data)) {
			throw new IllegalStateException("invalid pcap stream, error reading global header");
		}

		GlobalHeader result = new GlobalHeader();

		result.setMagicNumber(readInt(data, 0, false));

		result.setVersionMajor(readShort(data, 4, result.isSwapped()));
		result.setVersionMinor(readShort(data, 6, result.isSwapped()));
		result.setZone(readInt(data, 8, result.isSwapped()));
		result.setAccuracy(readInt(data, 12, result.isSwapped()));
		result.setMaxLength(readInt(data, 16, result.isSwapped()));
		result.setNetworkType(readInt(data, 20, result.isSwapped()));

		return result;
	}

	private static PacketHeader parsePacketHeader(InputStream inputStream, GlobalHeader globalHeader, int offset)
			throws IOException {
		byte[] data = new byte[16];

		int read = inputStream.read(data);

		if(-1 == read) {
			return null;
		}

		if(16 != read) {
			throw new IllegalStateException("invalid pcap stream, error reading packet header at offset: " + offset);
		}

		PacketHeader result = new PacketHeader();

		result.setEpochSeconds(readInt(data, 0, globalHeader.isSwapped()));
		result.setOffset(readInt(data, 4, globalHeader.isSwapped()));
		result.setActualLength(readInt(data, 8, globalHeader.isSwapped()));
		result.setOriginalLength(readInt(data, 12, globalHeader.isSwapped()));

		return result;
	}

	private static Packet parsePacket(InputStream inputStream, GlobalHeader globalHeader, int offset)
			throws IOException {
		PacketHeader packetHeader = parsePacketHeader(inputStream, globalHeader, offset);

		if(null == packetHeader) {
			return null;
		}

		Packet packet = new Packet();

		packet.setHeader(packetHeader);
		packet.setData(parseData(inputStream, offset + 24, packetHeader.getActualLength()));

		return packet;
	}

	private static byte[] parseData(InputStream inputStream, int offset, int length) throws IOException {
		byte[] result = new byte[length];

		if(length != inputStream.read(result)) {
			throw new IllegalStateException("invalid pcap stream, error reading packet data at offset: " + offset);
		}

		return result;
	}

	private static List<Packet> parsePacketList(InputStream inputStream, GlobalHeader globalHeader) throws IOException {
		List<Packet> result = new ArrayList<>();

		int offset = 25;

		while(true) {
			Packet packet = parsePacket(inputStream, globalHeader, offset);

			if(null == packet) {
				break;
			}

			result.add(packet);

			offset += 24 + packet.getHeader().getActualLength();
		}

		return result;
	}

	public static Pcap parse(InputStream inputStream) {
		try {
			Pcap result = new Pcap();

			result.setGlobalHeader(parseGlobalHeader(inputStream));
			result.setPacketList(parsePacketList(inputStream, result.getGlobalHeader()));

			return result;
		} catch(Exception e) {
			throw new PcapParserException(e);
		}
	}
}
