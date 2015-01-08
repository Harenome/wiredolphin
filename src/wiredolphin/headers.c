/**
 * \file headers.c
 * \brief Headers.
 * \author RAZANAJATO RANAIVOARIVONY Harenome
 * \date 2014
 * \copyright WTFPLv2
 */
/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://www.wtfpl.net/ for more details.
 */

#include "wiredolphin/headers.h"

////////////////////////////////////////////////////////////////////////////////
// Static utilities.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print the ethernet protocol ID.
 * \param stream Output stream.
 * \param protocol_id Protocol ID.
 */
static inline void __header_ethernet_print_protocol (FILE * stream,
        uint16_t protocol_id);

/**
 * \brief Print a MAC address.
 * \param stream Output stream.
 * \param address MAC address.
 */
static inline void __header_ethernet_print_mac (FILE * stream,
        const u_int8_t address[ETH_ALEN]);

/**
 * \brief Print an IPv4 header's flags.
 * \param stream Output stream.
 * \param flags_and_offset The flags/offset field of the IPv4 header.
 */
static inline void __header_ipv4_print_flags (FILE * stream,
        u_short flags_and_offset);

/**
 * \brief Print an IP encapsulated protocol.
 * \param stream Output stream.
 * \param protocol Protocol.
 */
static inline void __header_ip_print_protocol (FILE * stream,
        u_short protocol);

/**
 * \brief Print an ARP opcode.
 * \param stream Output stream.
 * \param code ARP opcode.
 */
static inline void __header_arp_print_opcode (FILE * stream,
        unsigned short int code);

/**
 * \brief Print an ICMP type.
 * \param stream Output stream.
 * \param type ICMP type.
 */
static inline void __header_icmp4_print_type (FILE * stream, u_int8_t type);

/**
 * \brief Print an ICMP sub code.
 * \param stream Output stream.
 * \param code ICMP sub code.
 */
static inline void __header_icmp4_print_code (FILE * stream, u_int8_t type,
        u_int8_t code);

/**
 * \brief Print an ICMP data.
 * \param stream Output stream.
 * \param header ICMP header
 */
static inline void __header_icmp4_print_data (FILE * stream,
        const struct icmphdr * header);

/**
 * \brief Print TCP flags.
 * \param stream Output stream.
 * \param flags TCP flags.
 */
static inline void __header_tcp4_print_flags (FILE * stream, u_int8_t flags);

/**
 * \brief List of IP protocols.
 *
 * According to Wikipedia(!):
 *
 *  0           0x00        HOPOPT              IPv6 Hop-by-Hop Option  RFC 2460
 *  1           0x01        ICMP                Internet Control Message Protocol   RFC 792
 *  2           0x02        IGMP                Internet Group Management Protocol  RFC 1112
 *  3           0x03        GGP                 Gateway-to-Gateway Protocol     RFC 823
 *  4           0x04        IP-in-IP            IP_in_IP (encapsulation)    RFC 2003
 *  5           0x05        ST                  Internet Stream Protocol    RFC 1190, RFC 1819
 *  6           0x06        TCP                 Transmission Control Protocol   RFC 793
 *  7           0x07        CBT                 Core-based trees    RFC 2189
 *  8           0x08        EGP                 Exterior Gateway Protocol   RFC 888
 *  9           0x09        IGP                 Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))     
 *  10          0x0A        BBN-RCC-MON         BBN RCC Monitoring  
 *  11          0x0B        NVP-II              Network Voice Protocol  RFC 741
 *  12          0x0C        PUP                 Xerox PUP   
 *  13          0x0D        ARGUS               ARGUS   
 *  14          0x0E        EMCON               EMCON   
 *  15          0x0F        XNET                Cross Net Debugger  IEN 158
 *  16          0x10        CHAOS               Chaos   
 *  17          0x11        UDP                 User Datagram Protocol  RFC 768
 *  18          0x12        MUX                 Multiplexing    IEN 90
 *  19          0x13        DCN-MEAS            DCN Measurement Subsystems  
 *  20          0x14        HMP                 Host Monitoring Protocol    RFC 869
 *  21          0x15        PRM                 Packet Radio Measurement    
 *  22          0x16        XNS-IDP             XEROX NS IDP    
 *  23          0x17        TRUNK-1             Trunk-1     
 *  24          0x18        TRUNK-2             Trunk-2     
 *  25          0x19        LEAF-1              Leaf-1  
 *  26          0x1A        LEAF-2              Leaf-2  
 *  27          0x1B        RDP                 Reliable Datagram Protocol  RFC 908
 *  28          0x1C        IRTP                Internet Reliable Transaction Protocol  RFC 938
 *  29          0x1D        ISO-TP4             ISO Transport Protocol Class 4  RFC 905
 *  30          0x1E        NETBLT              Bulk Data Transfer Protocol     RFC 998
 *  31          0x1F        MFE-NSP             MFE Network Services Protocol   
 *  32          0x20        MERIT-INP           MERIT Internodal Protocol   
 *  33          0x21        DCCP                Datagram Congestion Control Protocol    RFC 4340
 *  34          0x22        3PC                 Third Party Connect Protocol    
 *  35          0x23        IDPR                Inter-Domain Policy Routing Protocol    RFC 1479
 *  36          0x24        XTP                 Xpress Transport Protocol   
 *  37          0x25        DDP                 Datagram Delivery Protocol  
 *  38          0x26        IDPR-CMTP           IDPR Control Message Transport Protocol     
 *  39          0x27        TP++                TP++ Transport Protocol     
 *  40          0x28        IL                  IL Transport Protocol   
 *  41          0x29        IPv6                IPv6 Encapsulation  RFC 2473
 *  42          0x2A        SDRP                Source Demand Routing Protocol  RFC 1940
 *  43          0x2B        IPv6-Route          Routing Header for IPv6     RFC 2460
 *  44          0x2C        IPv6-Frag           Fragment Header for IPv6    RFC 2460
 *  45          0x2D        IDRP                Inter-Domain Routing Protocol   
 *  46          0x2E        RSVP                Resource Reservation Protocol   RFC 2205
 *  47          0x2F        GRE                 Generic Routing Encapsulation   RFC 2784, RFC 2890
 *  48          0x30        MHRP                Mobile Host Routing Protocol    
 *  49          0x31        BNA                 BNA     
 *  50          0x32        ESP                 Encapsulating Security Payload  RFC 4303
 *  51          0x33        AH                  Authentication Header   RFC 4302
 *  52          0x34        I-NLSP              Integrated Net Layer Security Protocol  TUBA
 *  53          0x35        SWIPE               SwIPe   IP with Encryption
 *  54          0x36        NARP                NBMA Address Resolution Protocol    RFC 1735
 *  55          0x37        MOBILE              IP Mobility (Min Encap)     RFC 2004
 *  56          0x38        TLSP                Transport Layer Security Protocol (using Kryptonet key management)   
 *  57          0x39        SKIP                Simple Key-Management for Internet Protocol     RFC 2356
 *  58          0x3A        IPv6-ICMP           ICMP for IPv6   RFC 4443, RFC 4884
 *  59          0x3B        IPv6-NoNxt          No Next Header for IPv6     RFC 2460
 *  60          0x3C        IPv6-Opts           Destination Options for IPv6    RFC 2460
 *  61          0x3D                            Any host internal protocol  
 *  62          0x3E        CFTP                CFTP    
 *  63          0x3F                            Any local network   
 *  64          0x40        SAT-EXPAK           SATNET and Backroom EXPAK   
 *  65          0x41        KRYPTOLAN           Kryptolan   
 *  66          0x42        RVD                 MIT Remote Virtual Disk Protocol    
 *  67          0x43        IPPC                Internet Pluribus Packet Core   
 *  68          0x44                            Any distributed file system     
 *  69          0x45        SAT-MON             SATNET Monitoring   
 *  70          0x46        VISA                VISA Protocol   
 *  71          0x47        IPCU                Internet Packet Core Utility    
 *  72          0x48        CPNX                Computer Protocol Network Executive     
 *  73          0x49        CPHB                Computer Protocol Heart Beat    
 *  74          0x4A        WSN                 Wang Span Network   
 *  75          0x4B        PVP                 Packet Video Protocol   
 *  76          0x4C        BR-SAT-MON          Backroom SATNET Monitoring  
 *  77          0x4D        SUN-ND              SUN ND PROTOCOL-Temporary   
 *  78          0x4E        WB-MON              WIDEBAND Monitoring     
 *  79          0x4F        WB-EXPAK            WIDEBAND EXPAK  
 *  80          0x50        ISO-IP              International Organization for Standardization Internet Protocol  
 *  81          0x51        VMTP                Versatile Message Transaction Protocol  RFC 1045
 *  82          0x52        SECURE-VMTP         Secure Versatile Message Transaction Protocol   RFC 1045
 *  83          0x53        VINES               VINES   
 *  84          0x54        TTP                 TTP     
 *  84          0x54        IPTM                Internet Protocol Traffic Manager   
 *  85          0x55        NSFNET-IGP          NSFNET-IGP  
 *  86          0x56        DGP                 Dissimilar Gateway Protocol     
 *  87          0x57        TCF                 TCF     
 *  88          0x58        EIGRP               EIGRP   
 *  89          0x59        OSPF                Open Shortest Path First    RFC 1583
 *  90          0x5A        Sprite-RPC          Sprite RPC Protocol     
 *  91          0x5B        LARP                Locus Address Resolution Protocol   
 *  92          0x5C        MTP                 Multicast Transport Protocol    
 *  93          0x5D        AX.25               AX.25   
 *  94          0x5E        IPIP                IP-within-IP Encapsulation Protocol     RFC 2003
 *  95          0x5F        MICP                Mobile Internetworking Control Protocol     
 *  96          0x60        SCC-SP              Semaphore Communications Sec. Pro   
 *  97          0x61        ETHERIP             Ethernet-within-IP Encapsulation    RFC 3378
 *  98          0x62        ENCAP               Encapsulation Header    RFC 1241
 *  99          0x63                            Any private encryption scheme   
 *  100         0x64        GMTP                GMTP    
 *  101         0x65        IFMP                Ipsilon Flow Management Protocol    
 *  102         0x66        PNNI                PNNI over IP    
 *  103         0x67        PIM                 Protocol Independent Multicast  
 *  104         0x68        ARIS                IBM's ARIS (Aggregate Route IP Switching) Protocol  
 *  105         0x69        SCPS                SCPS (Space Communications Protocol Standards)  SCPS-TP[1]
 *  106         0x6A        QNX                 QNX     
 *  107         0x6B        A/N                 Active Networks     
 *  108         0x6C        IPComp              IP Payload Compression Protocol     RFC 3173
 *  109         0x6D        SNP                 Sitara Networks Protocol    
 *  110         0x6E        Compaq-Peer         Compaq Peer Protocol    
 *  111         0x6F        IPX-in-IP           IPX in IP   
 *  112         0x70        VRRP                Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)   VRRP:RFC 3768
 *  113         0x71        PGM                 PGM Reliable Transport Protocol     RFC 3208
 *  114         0x72                            Any 0-hop protocol  
 *  115         0x73        L2TP                Layer Two Tunneling Protocol Version 3  RFC 3931
 *  116         0x74        DDX                 D-II Data Exchange (DDX)    
 *  117         0x75        IATP                Interactive Agent Transfer Protocol     
 *  118         0x76        STP                 Schedule Transfer Protocol  
 *  119         0x77        SRP                 SpectraLink Radio Protocol  
 *  120         0x78        UTI                 Universal Transport Interface Protocol  
 *  121         0x79        SMP                 Simple Message Protocol     
 *  122         0x7A        SM                  Simple Multicast Protocol   draft-perlman-simple-multicast-03
 *  123         0x7B        PTP                 Performance Transparency Protocol   
 *  124         0x7C        IS-IS over IPv4     Intermediate System to Intermediate System (IS-IS) Protocol over IPv4    RFC 1142 and RFC 1195
 *  125         0x7D        FIRE                Flexible Intra-AS Routing Environment   
 *  126         0x7E        CRTP                Combat Radio Transport Protocol     
 *  127         0x7F        CRUDP               Combat Radio User Datagram  
 *  128         0x80        SSCOPMCE            Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment  ITU-T Q.2111 (1999)
 *  129         0x81        IPLT        
 *  130         0x82        SPS                 Secure Packet Shield    
 *  131         0x83        PIPE                Private IP Encapsulation within IP  Expired I-D draft-petri-mobileip-pipe-00.txt
 *  132         0x84        SCTP                Stream Control Transmission Protocol    
 *  133         0x85        FC                  Fibre Channel   
 *  134         0x86        RSVP-E2E-IGNORE     Reservation Protocol (RSVP) End-to-End Ignore   RFC 3175
 *  135         0x87        Mobility Header     Mobility Extension Header for IPv6  RFC 6275
 *  136         0x88        UDPLite             Lightweight User Datagram Protocol  RFC 3828
 *  137         0x89        MPLS-in-IP          Multiprotocol Label Switching Encapsulated in IP    RFC 4023
 *  138         0x8A        manet               MANET Protocols     RFC 5498
 *  139         0x8B        HIP                 Host Identity Protocol  RFC 5201
 *  140         0x8C        Shim6               Site Multihoming by IPv6 Intermediation     RFC 5533
 *  141         0x8D        WESP                Wrapped Encapsulating Security Payload  RFC 5840
 *  142         0x8E        ROHC                Robust Header Compression   RFC 5856
 *  143-252     0x8F-0xFC                   UNASSIGNED
 *  253-254     0xFD-0xFE                   Use for experimentation and testing     RFC 3692
 *  255         0xFF                        Reserved
 */
static const char * __IP_PROTOCOLS[] =
{
    /* Non specified indexes are initialized to 0 or NULL. */
    [0]   = "HOPOPT",
    [1]   = "ICMP",
    [2]   = "IGMP",
    [3]   = "GGP",
    [4]   = "IP-in-IP",
    [5]   = "ST",
    [6]   = "TCP",
    [7]   = "CBT",
    [8]   = "EGP",
    [9]   = "IGP",
    [10]  = "BBN-RCC-MON",
    [11]  = "NVP-II",
    [12]  = "PUP",
    [13]  = "ARGUS",
    [14]  = "EMCON",
    [15]  = "XNET",
    [16]  = "CHAOS",
    [17]  = "UDP",
    [18]  = "MUX",
    [19]  = "DCN-MEAS",
    [20]  = "HMP",
    [21]  = "PRM",
    [22]  = "XNS-IDP",
    [23]  = "TRUNK-1",
    [24]  = "TRUNK-2",
    [25]  = "LEAF-1",
    [26]  = "LEAF-2",
    [27]  = "RDP",
    [28]  = "IRTP",
    [29]  = "ISO-TP4",
    [30]  = "NETBLT",
    [31]  = "MFE-NSP",
    [32]  = "MERIT-INP",
    [33]  = "DCCP",
    [34]  = "3PC",
    [35]  = "IDPR",
    [36]  = "XTP",
    [37]  = "DDP",
    [38]  = "IDPR-CMTP",
    [39]  = "TP++",
    [40]  = "IL",
    [41]  = "IPv6",
    [42]  = "SDRP",
    [43]  = "IPv6-Route",
    [44]  = "IPv6-Frag",
    [45]  = "IDRP",
    [46]  = "RSVP",
    [47]  = "GRE",
    [48]  = "MHRP",
    [49]  = "BNA",
    [50]  = "ESP",
    [51]  = "AH",
    [52]  = "I-NLSP",
    [53]  = "SWIPE",
    [54]  = "NARP",
    [55]  = "MOBILE",
    [56]  = "TLSP",
    [57]  = "SKIP",
    [58]  = "IPv6-ICMP",
    [59]  = "IPv6-NoNxt",
    [60]  = "IPv6-Opts",
    [61]  = "Any host internal protocol",
    [62]  = "CFTP",
    [63]  = "Any local network",
    [64]  = "SAT-EXPAK",
    [65]  = "KRYPTOLAN",
    [66]  = "RVD",
    [67]  = "IPPC",
    [68]  = "Any distributed file system",
    [69]  = "SAT-MON",
    [70]  = "VISA",
    [71]  = "IPCU",
    [72]  = "CPNX",
    [73]  = "CPHB",
    [74]  = "WSN",
    [75]  = "PVP",
    [76]  = "BR-SAT-MON",
    [77]  = "SUN-ND",
    [78]  = "WB-MON",
    [79]  = "WB-EXPAK",
    [80]  = "ISO-IP",
    [81]  = "VMTP",
    [82]  = "SECURE-VMTP",
    [83]  = "VINES",
    [84]  = "TTP",
    [85]  = "NSFNET-IGP",
    [86]  = "DGP",
    [87]  = "TCF",
    [88]  = "EIGRP",
    [89]  = "OSPF",
    [90]  = "Sprite-RPC",
    [91]  = "LARP",
    [92]  = "MTP",
    [93]  = "AX.25",
    [94]  = "IPIP",
    [95]  = "MICP",
    [96]  = "SCC-SP",
    [97]  = "ETHERIP",
    [98]  = "ENCAP",
    [99]  = "Any private encryption scheme",
    [100] = "GMTP",
    [101] = "IFMP",
    [102] = "PNNI",
    [103] = "PIM",
    [104] = "ARIS",
    [105] = "SCPS",
    [106] = "QNX",
    [107] = "A/N",
    [108] = "IPComp",
    [109] = "SNP",
    [110] = "Compaq-Peer",
    [111] = "IPX-in-IP",
    [112] = "VRRP",
    [113] = "PGM",
    [114] = "Any 0-hop protocol",
    [115] = "L2TP",
    [116] = "DDX",
    [117] = "IATP",
    [118] = "STP",
    [119] = "SRP",
    [120] = "UTI",
    [121] = "SMP",
    [122] = "SM",
    [123] = "PTP",
    [124] = "IS-IS over IPv4",
    [125] = "FIRE",
    [126] = "CRTP",
    [127] = "CRUDP",
    [128] = "SSCOPMCE",
    [129] = "IPLT",
    [130] = "SPS",
    [131] = "PIPE",
    [132] = "SCTP",
    [133] = "FC",
    [134] = "RSVP-E2E-IGNORE",
    [135] = "Mobility Header",
    [136] = "UDPLite",
    [137] = "MPLS-in-IP",
    [138] = "manet",
    [139] = "HIP",
    [140] = "Shim6",
    [141] = "WESP",
    [142] = "ROHC",
    [253] = "Experimentation and testing",
    [254] = "Experimentation and testing",
    [255] = "Reserved",
 
};

////////////////////////////////////////////////////////////////////////////////
// Ethernet frames.
////////////////////////////////////////////////////////////////////////////////

void header_ethernet_print_complete (FILE * const stream,
        const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;

    fprintf (stream, "Ethernet header\n===============\n");

    /* Print the source. */
    fprintf (stream, "%-12s\t", "Source:");
    __header_ethernet_print_mac (stream, header->ether_shost);
    fprintf (stream, "\n");

    /* Print the destination. */
    fprintf (stream, "%-12s\t", "Destination:");
    __header_ethernet_print_mac (stream, header->ether_dhost);
    fprintf (stream, "\n");

    /* Print the packet type. */
    fprintf (stream, "%-12s\t", "Packet type:");
    __header_ethernet_print_protocol (stream, ntohs (header->ether_type));
    fprintf (stream, "\n");

    fprintf (stream, "\n");
}

void header_ethernet_print_synthetic (FILE * const stream,
        const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;

    /* <source> -> <destination>, <packet type> */
    __header_ethernet_print_mac (stream, header->ether_shost);
    fprintf (stream, " -> ");
    __header_ethernet_print_mac (stream, header->ether_dhost);
    fprintf (stream, ", ");
    __header_ethernet_print_protocol (stream, ntohs (header->ether_type));
    fprintf (stream, "\n");
}

uint16_t header_ethernet_packet_type (const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;
    return ntohs (header->ether_type);
}

const u_char * header_ethernet_data (const u_char * bytes)
{
    return bytes + sizeof (struct ether_header);
}

////////////////////////////////////////////////////////////////////////////////
// IP headers.
////////////////////////////////////////////////////////////////////////////////

void header_ipv4_print_complete (FILE * const stream,
        const u_char * bytes)
{
    const struct iphdr * header = (const struct iphdr *) bytes;

    fprintf (stream, "IPv4 header\n===========\n");

    /* Version. */
    fprintf (stream, "%-16s\t%u\n", "Version:", header->version);

    /* Header length. */
    fprintf (stream, "%-16s\t%u\n", "IHL:", header->ihl);

    /* DSCP and ECN. */
    fprintf (stream, "%-16s\t%u\n", "DSCP:", IPTOS_DSCP (header->tos));
    fprintf (stream, "%-16s\t%u\n", "ECN:", IPTOS_ECN (header->tos));

    /* Total length. */
    fprintf (stream, "%-16s\t%u\n", "Total length:", header->tot_len);

    /* Identification. */
    fprintf (stream, "%-16s\t%u\n", "Identification:", header->id);

    /* Flags. */
    fprintf (stream, "%-16s\t", "Flags:");
    __header_ipv4_print_flags (stream, header->frag_off);
    fprintf (stream, "\n");

    /* TTL. */
    fprintf (stream, "%-16s\t%u\n", "TTL:", header->ttl);

    /* Protocol. */
    fprintf (stream, "%-16s\t", "Protocol:");
    __header_ip_print_protocol (stream, header->protocol);
    fprintf (stream, "\n");

    /* Source and destination addresses. */
    fprintf (stream, "%-16s\t%s\n", "Source:",
            inet_ntoa ((struct in_addr) { header->saddr }));
    fprintf (stream, "%-16s\t%s\n", "Destination:",
            inet_ntoa ((struct in_addr) { header->daddr }));

    fprintf (stream, "\n");
}

void header_ipv4_print_synthetic (FILE * const stream,
        const u_char * const bytes)
{
    const struct ip * header = (const struct ip *) bytes;

    fprintf (stream, "%s -> %s, ", inet_ntoa (header->ip_src),
            inet_ntoa (header->ip_dst));
    __header_ip_print_protocol (stream, header->ip_p);
    fprintf (stream, "\n");
}

void header_ipv4_print_concise (FILE * const stream,
        const u_char * const bytes)
{
    const struct ip * header = (const struct ip *) bytes;

    fprintf (stream, "%s -> %s, ", inet_ntoa (header->ip_src),
            inet_ntoa (header->ip_dst));
    __header_ip_print_protocol (stream, header->ip_p);
    fprintf (stream, "\n");
}

const u_char * header_ipv4_data (const u_char * bytes)
{
    const struct ip * header = (const struct ip *) bytes;
    return bytes + (header->ip_hl * 4);
}

u_int8_t header_ipv4_protocol (const u_char * bytes)
{
    const struct ip * header = (const struct ip *) bytes;
    return header->ip_p;
}

////////////////////////////////////////////////////////////////////////////////
// ARP headers.
////////////////////////////////////////////////////////////////////////////////

void header_arp_print_complete (FILE * const stream, const u_char * bytes)
{
    const struct arphdr * header = (const struct arphdr *) bytes;
    unsigned char hln = header->ar_hln;
    unsigned char pln = header->ar_pln;

    fprintf (stream, "ARP header\n==========\n");

    /* Hardware type. */
    fprintf (stream, "%-24s\t%u\n", "Hardware type:", header->ar_hrd);

    /* Protocol. */
    fprintf (stream, "%-24s\t", "Protocol:");
    __header_ethernet_print_protocol (stream, header->ar_pro);
    fprintf (stream, "\n");

    /* Lengths. */
    fprintf (stream, "%-24s\t%u\n", "Hardware length:", hln);
    fprintf (stream, "%-24s\t%u\n", "Protocol length:", pln);

    /* Operation code. */
    fprintf (stream, "%-24s\t", "Operation code:");
    __header_arp_print_opcode (stream, header->ar_op);
    fprintf (stream, "\n");

    const u_char * addresses = bytes + sizeof (struct arphdr);

    /* Sender hardware address. */
    if (hln == ETH_ALEN)
        fprintf (stream, "%-24s\t%s\n", "Sender hardware address:",
            ether_ntoa ((const struct ether_addr *) addresses));

    /* Sender protocol address. */
    addresses += hln;
    if (pln == 4)
        fprintf (stream, "%-24s\t%s\n", "Sender protocol address:",
            inet_ntoa (* ((const struct in_addr *) addresses)));

    /* Target hardware address. */
    addresses += pln;
    if (hln == ETH_ALEN)
        fprintf (stream, "%-24s\t%s\n", "Target hardware address:",
            ether_ntoa ((const struct ether_addr *) addresses));

    /* Target protocol address. */
    addresses += hln;
    if (pln == 4)
        fprintf (stream, "%-24s\t%s\n", "Target protocol address:",
            inet_ntoa (* ((const struct in_addr *) addresses)));

    fprintf (stream, "\n");
}

void header_arp_print_synthetic (FILE * const stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

void header_arp_print_concise (FILE * const stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

////////////////////////////////////////////////////////////////////////////////
// ICMP headers.
////////////////////////////////////////////////////////////////////////////////

void header_icmp4_print_complete (FILE * stream, const u_char * bytes)
{
    const struct icmphdr * header = (const struct icmphdr *) bytes;
    u_int8_t type = header->type;
    u_int8_t code = header->code;

    fprintf (stream, "ICMP header\n===========\n");

    /* Type. */
    fprintf (stream, "%-5s\t", "Type:");
    __header_icmp4_print_type (stream, type);
    fprintf (stream, "\n");

    /* Subcode. */
    if (type == ICMP_DEST_UNREACH || type == ICMP_REDIRECT
            || type == ICMP_TIME_EXCEEDED || type == ICMP_PARAMETERPROB)
    {
        fprintf (stream, "%-5s\t", "Code:");
        __header_icmp4_print_code (stream, type, code);
        fprintf (stream, "\n");
    }

    __header_icmp4_print_data (stream, header);

    fprintf (stream, "\n");
}

void header_icmp4_print_synthetic (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

void header_icmp4_print_concise (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

////////////////////////////////////////////////////////////////////////////////
// TCP headers.
////////////////////////////////////////////////////////////////////////////////

void header_tcp4_print_complete (FILE * stream, const u_char * bytes)
{
    const struct tcphdr * header = (const struct tcphdr *) bytes;

    fprintf (stream, "TCP header\n==========\n");

    fprintf (stream, "%-24s\t%u\n", "Source port:", header->th_sport);
    fprintf (stream, "%-24s\t%u\n", "Destination port:", header->th_dport);
    fprintf (stream, "%-24s\t%u\n", "Sequence number:", header->th_seq);
    fprintf (stream, "%-24s\t%u\n", "Acknowledgement number:", header->th_ack);
    fprintf (stream, "%-24s\t%u\n", "Data offset:", header->th_off);

    fprintf (stream, "%-24s\t", "Flags:");
    __header_tcp4_print_flags (stream, header->th_flags);
    fprintf (stream, "\n");

    fprintf (stream, "%-24s\t%u\n", "Window:", header->th_win);
    fprintf (stream, "%-24s\t%u\n", "Urgen pointer:", header->th_win);

}

void header_tcp4_print_synthetic (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

void header_tcp4_print_concise (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

const u_char * header_tcp4_data (const u_char * bytes)
{
    const struct tcphdr * header = (const struct tcphdr *) bytes;
    return bytes + (header->th_off * 4);
}


////////////////////////////////////////////////////////////////////////////////
// UDP headers.
////////////////////////////////////////////////////////////////////////////////

void header_udp4_print_complete (FILE * stream, const u_char * bytes)
{
    const struct udphdr * header = (const struct udphdr *) bytes;

    fprintf (stream, "UDP header\n==========\n");

    fprintf (stream, "%-20s\t%u\n", "Source port:", header->uh_sport);
    fprintf (stream, "%-20s\t%u\n", "Destination port:", header->uh_sport);
    fprintf (stream, "%-20s\t%u\n", "Length:", header->uh_ulen);

    fprintf (stream, "\n");
}

void header_udp4_print_synthetic (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

void header_udp4_print_concise (FILE * stream, const u_char * bytes)
{
    (void) stream; (void) bytes;
}

const u_char * header_udp4_data (const u_char * bytes)
{
    return bytes + sizeof (struct udphdr);
}


////////////////////////////////////////////////////////////////////////////////
// Misc.
////////////////////////////////////////////////////////////////////////////////

void __header_ethernet_print_protocol (FILE * const stream,
        uint16_t protocol_id)
{
    const char * protocol_string = "";
    switch (protocol_id)
    {
        case ETHERTYPE_PUP:
            protocol_string = "Xerox PUP"; break;
        case ETHERTYPE_SPRITE:
            protocol_string = "Sprite"; break;
        case ETHERTYPE_IP:
            protocol_string = "IP"; break;
        case ETHERTYPE_ARP:
            protocol_string = "ARP"; break;
        case ETHERTYPE_REVARP:
            protocol_string = "Reverse ARP"; break;
        case ETHERTYPE_AT:
            protocol_string = "AppleTalk Protocol"; break;
        case ETHERTYPE_AARP:
            protocol_string = "AppleTalk ARP"; break;
        case ETHERTYPE_VLAN:
            protocol_string = "IEEE 802.1Q VLAN tagging"; break;
        case ETHERTYPE_IPX:
            protocol_string = "IPX"; break;
        case ETHERTYPE_IPV6:
            protocol_string = "IPv6"; break;
        case ETHERTYPE_LOOPBACK:
            protocol_string = "Test"; break;
        default:
            protocol_string = "Unknown"; break;
    }
    fprintf (stream, "%s", protocol_string);
}

void __header_ethernet_print_mac (FILE * const stream,
        const u_int8_t address[ETH_ALEN])
{
    /* Print the subparts of the address, separated by colons. */
    for (size_t i = 0; i < ETH_ALEN; ++i)
        fprintf (stream, "%.2x%c", address[i], i < ETH_ALEN - 1 ? ':' : '\0');
}

void __header_ipv4_print_flags (FILE * const stream, u_short flags_and_offset)
{
    bool df = flags_and_offset & IP_DF;
    bool mf = flags_and_offset & IP_MF;

    fprintf (stream, "%s%c%s",
            df ? "Don't fragment" : "",
            df && mf ? ',' : '\0',
            mf ? "More fragments" : (df ? "" : "No flags"));
}

void __header_ip_print_protocol (FILE * const stream,
        u_short protocol)
{
    if (protocol >= 143 && protocol <= 252)
        fprintf (stream, "UNASSIGNED");
    else
        fprintf (stream, "%s", __IP_PROTOCOLS[protocol]);
}

void __header_arp_print_opcode (FILE * const stream,
        unsigned short int code)
{
    const char * protocol_string = "";
    switch (code)
    {
        case ARPOP_REQUEST:
            protocol_string = "ARP request"; break;
        case ARPOP_REPLY:
            protocol_string = "ARP reply"; break;
        case ARPOP_RREQUEST:
            protocol_string = "RARP request"; break;
        case ARPOP_RREPLY:
            protocol_string = "RARP reply"; break;
        case ARPOP_InREQUEST:
            protocol_string = "InARP request"; break;
        case ARPOP_InREPLY:
            protocol_string = "InARP reply"; break;
        case ARPOP_NAK:
            protocol_string = "(ATM)ARP NAK"; break;
        default:
            protocol_string = "Unknown"; break;
    }
    fprintf (stream, "%s", protocol_string);
}

void __header_icmp4_print_type (FILE * const stream, u_int8_t type)
{
    static const char * icmp_types[] =
    {
        [ICMP_ECHOREPLY]      = "Echo reply",
        [ICMP_DEST_UNREACH]   = "Destination unreachable",
        [ICMP_SOURCE_QUENCH]  = "Source quench",
        [ICMP_REDIRECT]       = "Redirect",
        [ICMP_ECHO]           = "Echo request",
        [ICMP_TIME_EXCEEDED]  = "Time exceeded",
        [ICMP_PARAMETERPROB]  = "Parameter problem",
        [ICMP_TIMESTAMP]      = "Timestamp request",
        [ICMP_TIMESTAMPREPLY] = "Timestamp reply",
        [ICMP_INFO_REQUEST]   = "Information request",
        [ICMP_INFO_REPLY]     = "Information reply",
        [ICMP_ADDRESS]        = "Address mask request",
        [ICMP_ADDRESSREPLY]   = "Address mask reply",
    };

    fprintf (stream, "%s", type <= NR_ICMP_TYPES ? icmp_types[type] : "Unknown");
}

void __header_icmp4_print_code (FILE * const stream, u_int8_t type,
        u_int8_t code)
{
    static const char * unreach_codes[] =
    {
        [ICMP_NET_UNREACH]    = "Network unreachable",
        [ICMP_HOST_UNREACH]   = "Host unreachable",
        [ICMP_PROT_UNREACH]   = "Protocol unreachable",
        [ICMP_PORT_UNREACH]   = "Port unreachable",
        [ICMP_FRAG_NEEDED]    = "Fragmentation Needed/DF set",
        [ICMP_SR_FAILED]      = "Source Route failed",
        [ICMP_NET_UNKNOWN]    = "Destination network unknown",
        [ICMP_HOST_UNKNOWN]   = "Destination host unknown",
        [ICMP_HOST_ISOLATED]  = "Source host isolated",
        [ICMP_NET_ANO]        = "Network administratively prohibited",
        [ICMP_HOST_ANO]       = "Host administratively prohibited",
        [ICMP_NET_UNR_TOS]    = "Network unreachable for TOS",
        [ICMP_HOST_UNR_TOS]   = "Host unreachable for TOS",
        [ICMP_PKT_FILTERED]   = "Packet filtered",
        [ICMP_PREC_VIOLATION] = "Precedence violation",
        [ICMP_PREC_CUTOFF]    = "Precedence cut off",
    };
    static const char * redirect_codes[] =
    {
        [ICMP_REDIR_NET]     = "Redirect datagram for the network",
        [ICMP_REDIR_HOST]    = "Redirect datagram for the host",
        [ICMP_REDIR_NETTOS]  = "Redirect datagram for the TOS and the network",
        [ICMP_REDIR_HOSTTOS] = "Redirect datagram for the TOS and the host",
    };
    static const char * time_exceeded_codes[] =
    {
        [ICMP_EXC_TTL]      = "TTL count exceeded",
        [ICMP_EXC_FRAGTIME] = "Fragment reassembly time exceeded",
    };
    static const char * parameterprob_codes[] =
    {
        [0] = "Pointer indicates the error",
        [1] = "Missing a required option",
        [2] = "Bad length",
    };

    const char * string = "";
    switch (type)
    {
        case ICMP_DEST_UNREACH:
            string = code <= NR_ICMP_UNREACH ? unreach_codes[code] : ""; break;
        case ICMP_REDIRECT:
            string = code <= 3 ? redirect_codes[code] : ""; break;
        case ICMP_TIME_EXCEEDED:
            string = code <= 1 ? time_exceeded_codes[code] : ""; break;
        case ICMP_PARAMETERPROB:
            string = code <= 2 ? parameterprob_codes[code] : ""; break;
        default:
            break;
    }
    fprintf (stream, "%s", string);
}

void __header_icmp4_print_data (FILE * const stream,
        const struct icmphdr * header)
{
    if ((header->type == ICMP_ECHOREPLY && header->code == 0)
            || (header->type == ICMP_ECHOREPLY && header->code == 0))
    {
        fprintf (stream, "%-5s\t%u\n%-5s\t%u", "ID:", header->un.echo.id,
                "Seq:", header->un.echo.sequence);
    }
}

void __header_tcp4_print_flags (FILE * const stream, u_int8_t flags)
{
    flags &= 127;

    if (! flags)
        fprintf (stream, "None");
    else
    {
        if (flags & TH_FIN)
            fprintf (stream, "FIN%c", flags > TH_FIN ? ',' : '\0');
        if (flags & TH_SYN)
            fprintf (stream, "SYN%c", flags > TH_SYN ? ',' : '\0');
        if (flags & TH_RST)
            fprintf (stream, "RST%c", flags > TH_RST ? ',' : '\0');
        if (flags & TH_PUSH)
            fprintf (stream, "PUSH%c", flags > TH_PUSH ? ',' : '\0');
        if (flags & TH_ACK)
            fprintf (stream, "ACK%c", flags > TH_ACK ? ',' : '\0');
        if (flags & TH_URG)
            fprintf (stream, "URG%c", flags > TH_URG);
    }
}
