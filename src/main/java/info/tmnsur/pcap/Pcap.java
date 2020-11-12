package info.tmnsur.pcap;

import java.util.List;

public class Pcap {
	private GlobalHeader globalHeader;
	private List<Packet> packetList;

	public GlobalHeader getGlobalHeader() {
		return globalHeader;
	}

	public void setGlobalHeader(GlobalHeader globalHeader) {
		this.globalHeader = globalHeader;
	}

	public List<Packet> getPacketList() {
		return packetList;
	}

	public void setPacketList(List<Packet> packetList) {
		this.packetList = packetList;
	}
}
