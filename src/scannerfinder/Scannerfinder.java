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
 * @author Tim Wells
 */
public class Scannerfinder {

    /**
     * @param args the command line arguments
     */
    final static Ip4 ip = new Ip4();
    public static Hashtable<String, int[]> hash = new Hashtable<String, int[]>();
    public static int count = 0;

    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        String file = args[0];
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(file, errbuf);
        if (pcap == null) {
            throw new IOException(errbuf.toString());
        }
        pcap.loop(-1, pcappackethandler, file);
        System.out.println("\n" + count + " packets examined. Suspicious IP addresses:\n------------------------------------------------------------------------------------------------");
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            int[] vals = hash.get(key);
            float ratio = 0;
            if (vals[1] > 0) {
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
