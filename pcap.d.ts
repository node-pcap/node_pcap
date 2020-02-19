/// <reference types="node" />
import { EventEmitter } from 'events';

// FIXME: write rest of the typings
export const decode: any;
export const TCPTracker: any;
export const TCPSession: any;
export const DNSCache: any;

/**
 * format of the link-layer headers; `LINKTYPE_<...>` string, see
 * [this list](https://www.tcpdump.org/linktypes.html).
 */
export type LinkType = 'LINKTYPE_NULL' | 'LINKTYPE_ETHERNET' | 'LINKTYPE_IEEE802_11_RADIO' | 'LINKTYPE_RAW' | 'LINKTYPE_LINUX_SLL';

export interface CaptureStats {
    /** number of packets received */
    ps_recv: number;
    /** number of packets dropped by the network interface or its driver */
    ps_ifdrop: number;
    /**
     * number of packets dropped because there was no room in the operating
     * system's buffer when they arrived, because packets weren't being read fast enough
     */
    ps_drop: number;
}

/** Capture session object */
export declare class PcapSession extends EventEmitter {
    private constructor();

    /** Top-level headers in the packets */
    readonly link_type: LinkType;

    /**
     * Close the capture session. No more `packet` events will be
     * emitted.
     */
    close(): void;

    /**
     * Get current capture statistics
     * 
     * The statistics do not behave the same way on all platforms.
     * `ps_recv` might count packets whether they passed the filter or not,
     * or it might count only packets that pass the filter. It also might,
     * or might not, count packets dropped because there was no room in the
     * operating system's buffer when they arrived.
     * 
     * `ps_drop` is not available on all platforms; it is zero on platforms
     * where it's not available. If packet filtering is done in libpcap,
     * rather than in the operating system, it would count packets that
     * don't pass the filter.
     * 
     * Both `ps_recv` and `ps_drop` might, or might not,
     * count packets not yet read from the operating system and thus not
     * yet seen by the application.
     * 
     * `ps_ifdrop` might, or might not, be
     * implemented; if it's zero, that might mean that no packets were dropped
     * by the interface, or it might mean that the statistic is unavailable,
     * so it should not be treated as an indication that the interface
     * did not drop any packets.
     */
    stats(): CaptureStats;

    /** Inject a packet into the interface */
    inject(data: Buffer): void;
}

export interface PacketWithHeader {
    /** Raw packet bytes read by libpcap */
    buf: Buffer;
    /** Encoded information about the packet (timestamp, size) */
    header: Buffer;
    /** Top-level headers in `buf` */
    link_type: LinkType;
}

export interface CommonSessionOptions {
    /**
     * pcap filter expression, see `pcap-filter(7)` for more information.
     * (default: no filter, all packets visible on the interface will be captured)
     */
    filter?: string;
}

export interface LiveSessionOptions extends CommonSessionOptions {
    /**
     * size of the ringbuffer where packets are stored until delivered to your code, in bytes (default: 10MB)
     * 
     * > Packets that arrive for a capture are stored in a buffer, so that they do not have to be read by the application as soon as they arrive. On some platforms, the buffer's size can be set; a size that's too small could mean that, if too many packets are being captured and the snapshot length doesn't limit the amount of data that's buffered, packets could be dropped if the buffer fills up before the application can read packets from it, while a size that's too large could use more non-pageable operating system memory than is necessary to prevent packets from being dropped.
     */
    buffer_size?: number;

    /**
     * specifies if the interface is opened in promiscuous mode (default: true)
     *
     * > On broadcast LANs such as Ethernet, if the network isn't switched, or if the adapter is connected to a "mirror port" on a switch to which all packets passing through the switch are sent, a network adapter receives all packets on the LAN, including unicast or multicast packets not sent to a network address that the network adapter isn't configured to recognize.
     * > 
     * > Normally, the adapter will discard those packets; however, many network adapters support "promiscuous mode", which is a mode in which all packets, even if they are not sent to an address that the adapter recognizes, are provided to the host. This is useful for passively capturing traffic between two or more other hosts for analysis.
     * > 
     * > Note that even if an application does not set promiscuous mode, the adapter could well be in promiscuous mode for some other reason.
     * > 
     * > For now, this doesn't work on the "any" device; if an argument of "any" or NULL is supplied, the setting of promiscuous mode is ignored.
     */
    promiscuous?: boolean;

    /**
     * packet buffer timeout in milliseconds (default: 1000)
     *
     * > If, when capturing, packets are delivered as soon as they arrive, the application capturing the packets will be woken up for each packet as it arrives, and might have to make one or more calls to the operating system to fetch each packet.
     * >
     * > If, instead, packets are not delivered as soon as they arrive, but are delivered after a short delay (called a "packet buffer timeout"), more than one packet can be accumulated before the packets are delivered, so that a single wakeup would be done for multiple packets, and each set of calls made to the operating system would supply multiple packets, rather than a single packet. This reduces the per-packet CPU overhead if packets are arriving at a high rate, increasing the number of packets per second that can be captured.
     * >
     * > The packet buffer timeout is required so that an application won't wait for the operating system's capture buffer to fill up before packets are delivered; if packets are arriving slowly, that wait could take an arbitrarily long period of time.
     * >
     * > Not all platforms support a packet buffer timeout; on platforms that don't, the packet buffer timeout is ignored. A zero value for the timeout, on platforms that support a packet buffer timeout, will cause a read to wait forever to allow enough packets to arrive, with no timeout. A negative value is invalid; the result of setting the timeout to a negative value is unpredictable.
     * >
     * > **NOTE:** the packet buffer timeout cannot be used to cause calls that read packets to return within a limited period of time, because, on some platforms, the packet buffer timeout isn't supported, and, on other platforms, the timer doesn't start until at least one packet arrives. This means that the packet buffer timeout should **NOT** be used, for example, in an interactive application to allow the packet capture loop to ``poll'' for user input periodically, as there's no guarantee that a call reading packets will return after the timeout expires even if no packets have arrived.
     *
     * If set to zero or negative, then instead immediate mode is enabled:
     *
     * > In immediate mode, packets are always delivered as soon as they arrive, with no buffering.
     */    
    buffer_timeout?: number

    /**
     * specifies if monitor mode is enabled (default: false)
     *
     * > On IEEE 802.11 wireless LANs, even if an adapter is in promiscuous mode, it will supply to the host only frames for the network with which it's associated. It might also supply only data frames, not management or control frames, and might not provide the 802.11 header or radio information pseudo-header for those frames.
     * >
     * > In "monitor mode", sometimes also called "rfmon mode" (for "Radio Frequency MONitor"), the adapter will supply all frames that it receives, with 802.11 headers, and might supply a pseudo-header with radio information about the frame as well.
     * >
     * > Note that in monitor mode the adapter might disassociate from the network with which it's associated, so that you will not be able to use any wireless networks with that adapter. This could prevent accessing files on a network server, or resolving host names or network addresses, if you are capturing in monitor mode and are not connected to another network with another adapter.
     */
    monitor?: boolean

    /**
     * snapshot length in bytes (default: 65535)
     *
     * > If, when capturing, you capture the entire contents of the packet, that requires more CPU time to copy the packet to your application, more disk and possibly network bandwidth to write the packet data to a file, and more disk space to save the packet. If you don't need the entire contents of the packet - for example, if you are only interested in the TCP headers of packets - you can set the "snapshot length" for the capture to an appropriate value. If the snapshot length is set to snaplen, and snaplen is less than the size of a packet that is captured, only the first snaplen bytes of that packet will be captured and provided as packet data.
     * >
     * > A snapshot length of 65535 should be sufficient, on most if not all networks, to capture all the data available from the packet.
     */
    snap_length?: number
}

export interface OfflineSessionOptions extends CommonSessionOptions {
}

/**
 * Creates a live capture session on the specified device,
 * and starts capturing packets.
 * 
 * @param device name of the interface to capture on
 * @param options capture options
 */
export declare function createSession(device: string, options?: LiveSessionOptions): PcapSession;

/**
 * Starts an 'offline' capture session that emits packets
 * read from a capture file.
 * 
 * @param path filename of the `.pcap` file to read
 * @param options capture options
 */
export declare function createOfflineSession(path: string, options?: OfflineSessionOptions): PcapSession;

export interface Address {
    addr: string;
    netmask: string;
    broadaddr?: string;
}

export interface Device {
    name: string;
    addresses?: Address[];
    description?: string;
    flags?: string;
}

export declare function findalldevs(): Device[];

/** libpcap version string */
export const lib_version: string;

/**
 * This function is called whenever libpcap emits a warning, for
 * instance when an interface has no addresses. You may override it
 * to handle warnings in a different way.
 */
export let warningHandler: (text: string) => any;
