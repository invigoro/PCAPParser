/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package scannerfinder;

import java.io.File;
import java.io.IOException;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.util.PcapPacketArrayList;
/**
 *
 * @author Tim
 */
public class Scannerfinder {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        String file = "capture.pcap";
        System.out.println(args[0]);
        List<PcapPacket> list = getPacketList(file);
        for(int i = 0; i < list.size(); i++)
        {
            System.out.println(list.get(0));
        }
    }
    static public List<PcapPacket> getPacketList(String file) throws IOException {
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(file, errbuf);
        if(pcap == null) {
            throw new IOException(errbuf.toString());
        }
        final PcapPacketArrayList list = new PcapPacketArrayList((int) new File(file).length() / 100);
        pcap.loop(Pcap.LOOP_INFINATE, list, null);
        pcap.close();
        return list;
        
    }
    
}
