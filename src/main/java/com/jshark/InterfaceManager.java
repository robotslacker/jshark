package com.jshark;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import java.util.List;

/**
 * Manages network interface discovery and selection
 */
public class InterfaceManager {
    /**
     * Get all available network interfaces
     * @return list of network interfaces
     * @throws PcapNativeException if interface enumeration fails
     */
    public List<PcapNetworkInterface> getAllInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    /**
     * Get a network interface by IP address
     * @param ipAddress IP address as string (null or empty for default interface)
     * @return network interface or null if not found
     */
    public PcapNetworkInterface getInterface(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            throw new PacketCaptureException("IP address is null.");
        }

        // Get PCAP interface information based on IP address
        try {
            List<PcapNetworkInterface> interfaces = getAllInterfaces();

            for (PcapNetworkInterface networkInterface : interfaces) {
                for (PcapAddress address : networkInterface.getAddresses()) {
                    if (address.getAddress() != null) {
                        // Get IP address string, remove possible slash prefix
                        String interfaceIp = address.getAddress().getHostAddress();
                        // Exact match IP address
                        if (interfaceIp.equals(ipAddress)) {
                            return networkInterface;
                        }
                    }
                }
            }
            throw new PacketCaptureException("NO NIC matched. Failed to get network interface with ip address [{" + ipAddress + "}].");
        } catch (PcapNativeException e) {
            throw new PacketCaptureException("Failed to get network interface with ip address [{" + ipAddress + "}].", e);
        }
    }
}
