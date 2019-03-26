package scannerfinder;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.util.PcapPacketArrayList;

/**
 *
 * @author Tim Wells and Cory Peterson
 */
public class Scannerfinder {

    /**
     * @param arg[0] is the filepath to the pcap file
     */
    
    
    final static Ip4 ip = new Ip4(); //used for retreiving IP addresses
    public static Hashtable<String, int[]> hash = new Hashtable<String, int[]>();   //Stores IP address as key, and int[2] array where [0] is number of sent packets and [1] is number received
    public static int count = 0; //number of packets parsed

    public static void main(String[] args) throws IOException {
        // filepath of pcap file
        String file = args[0];
        
        //open and read the packet
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(file, errbuf);
        if (pcap == null) {
            throw new IOException(errbuf.toString());
        }
        pcap.loop(-1, pcappackethandler, file);
        
        //Print results
        System.out.println("\n" + count + " packets examined. Suspicious IP addresses:\n------------------------------------------------------------------------------------------------");
        //Iterate through the hashtable 
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            int[] vals = hash.get(key);
            float ratio = 0;    //ratio of sent to received
            if (vals[1] > 0) {  //so we don't accidentally divide by zero. Oops
                ratio = (float) ((float) vals[0] / (float) vals[1]);
            }
            if (ratio > 3) {
                System.out.println("IP address: " + key + "\t\tSent: " + vals[0] + "\tReceived: " + vals[1] + "\tS/R Ratio: " + ratio);
            }
        }

    }
    
    //method for breaking down each packet and getting source/dest ip addresses
    public static PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
        public void nextPacket(PcapPacket pcappacket, String user) {
            //System.out.println(pcappacket);
            if (pcappacket.hasHeader(ip)) {
                String source = FormatUtils.ip(ip.source());
                String dest = FormatUtils.ip(ip.destination());
                //System.out.println();
                //System.out.println("IP type:\t" + ip.typeEnum());
                //System.out.println("IP src:\t-\t" + source);
                //System.out.println("IP dst:\t-\t" + dest);
                
                //add to number of sent/received for ip in hashtable
                if (hash.containsKey(source)) {
                    int[] val = hash.get(source);
                    val[0]++;
                    hash.put(source, val);
                } else {
                    int[] val = {0, 0};
                    hash.put(source, val);
                }
                if (hash.containsKey(dest)) {
                    int[] val = hash.get(dest);
                    val[1]++;
                    hash.put(dest, val);
                } else {
                    int[] val = {0, 0};
                    hash.put(dest, val);
                }

                count++;
                if (count % 100000 == 0) {
                    System.out.println(count + " packets examined...");
                }
            }
        }
    };
}
