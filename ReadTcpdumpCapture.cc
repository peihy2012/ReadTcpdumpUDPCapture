#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>

using namespace std;

constexpr unsigned char DstMacSelected[6] = {0x00,0x30,0x64,0x51,0xa1,0x32};
constexpr int CanetPacketLength = 13;

// litte-endian as default in g++
// big-endian as default in UDP
unsigned short int changeEndian16(const unsigned short int input)
{
    unsigned short int output = (input >> 8)&0x00FF;
    output += (input << 8)&0xFF00;
    return output;
}
// big-endian as default in UDP
unsigned int changeEndian32(const unsigned int input)
{
    unsigned int output = (input >> 24)&0x000000FF;
    output += (input >> 8)&0x0000FF00;
    output += (input << 8)&0x00FF0000;
    output += (input << 24)&0xFF000000;
    return output;
}

void outputSize (void) 
{
    cout << "size of int " << sizeof(int) << endl;
    cout << "size of short int " << sizeof(short int) << endl;
    cout << "size of float " << sizeof(float) << endl;
    cout << "size of double " << sizeof(double) << endl;
}


namespace tcpdump {
    #pragma pack(1)
    union item {
        char data[1024];
        struct pkt {
            int sec;
            int usec;
            int inSize;
            int outSize;
            union udp {
                unsigned char data[1024];
                struct frame {
                    unsigned char macDst[6];
                    unsigned char macSrc[6];
                    unsigned short int ipType;
                    unsigned char version;
                    unsigned char field;
                    unsigned short int totalLength;
                    unsigned short int identification;
                    unsigned short int flags;
                    unsigned char timeToLive;
                    unsigned char protocol;
                    unsigned short int headerChecksum;
                    unsigned char srcIP[4];
                    unsigned char dstIP[4];
                    unsigned short int srcPort;
                    unsigned short int dstPort;
                    unsigned short int length;
                    unsigned short int checksum;
                    unsigned char data[1024];
                } frame;
            } udp;
        } pkt;
    };
    #pragma pack(1)
    union canMsg {
        unsigned char data[13];
        struct msg {
            unsigned char DLC      :4;  // Data length,0<=DLC<=8
            unsigned char reserved :2;
            unsigned char RTR      :1;  // 1 for remote request
            unsigned char FF       :1;  // Frame form. 1 = Extended, 0 = Standard
            unsigned int  ID;           // ID of message
            unsigned char data[8];      // Data of message
        } msg;
    };

    void testUdpFrame (union item& item)
    {
        cout << *dec ;
        cout << "sec: " << item.pkt.sec << endl;
        cout << "usec: " << item.pkt.usec << endl;
        cout << "inSize: " << item.pkt.inSize << endl;
        cout << "outSize " << item.pkt.outSize << endl;
        cout << hex;
        cout << "Destination Mac: " << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[0] 
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[1]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[2]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[3]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[4]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macDst[5]
            << endl;
        cout << hex;
        cout << "Source Mac: " << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[0] 
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[1]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[2]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[3]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[4]
            << ":" << setfill('0') << setw(2) 
            << (unsigned int)(unsigned char)item.pkt.udp.frame.macSrc[5]
            << endl;
        cout << *dec ;
        cout << "IP Type: " << changeEndian16(item.pkt.udp.frame.ipType) << endl;
        cout << "Version: " << (unsigned int)(unsigned char)item.pkt.udp.frame.version << endl;
        cout << "Field: " << (unsigned int)(unsigned char)item.pkt.udp.frame.field << endl;
        cout << "Total Length: " << changeEndian16(item.pkt.udp.frame.totalLength) << endl;
        cout << "Identification: " << changeEndian16(item.pkt.udp.frame.identification) << endl;
        cout << "Flags: " << changeEndian16(item.pkt.udp.frame.flags) << endl;
        cout << "Time to Live: " << (unsigned int)(unsigned char)item.pkt.udp.frame.timeToLive << endl;
        cout << "Protocol: " << (unsigned int)(unsigned char)item.pkt.udp.frame.protocol << endl;
        cout << "Header Checksum: " << changeEndian16(item.pkt.udp.frame.headerChecksum) << endl;
        cout << "Source IP: " << (unsigned int)(unsigned char)item.pkt.udp.frame.srcIP[0] 
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.srcIP[1] 
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.srcIP[2]
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.srcIP[3]
            << endl;
        cout << "Destination IP: " << (unsigned int)(unsigned char)item.pkt.udp.frame.dstIP[0] 
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.dstIP[1] 
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.dstIP[2]
            << "." << (unsigned int)(unsigned char)item.pkt.udp.frame.dstIP[3]
            << endl;
        cout << "Source Port: " << changeEndian16(item.pkt.udp.frame.srcPort) << endl;
        cout << "Destination Port: " << changeEndian16(item.pkt.udp.frame.dstPort) << endl;
        cout << "length: " << changeEndian16(item.pkt.udp.frame.length) << endl;
        cout << "Checksum: " << changeEndian16(item.pkt.udp.frame.checksum) << endl;

    }
};





int main (int argc, char** argv)
{
    ifstream infile; 
    infile.open("test.cap", ios::in | ios::binary); 
    cout << argv[0] << " reading from the file, argc = " << argc << endl; 
    int startPos = infile.tellg();
    cout << "start at " << startPos << endl;
    infile.seekg(0, ios::end);
    int endPos = infile.tellg();
    cout << "end at " << endPos << endl;
    int fileSize = endPos+1;
    infile.seekg(0);
    char* buf = new char[fileSize];
    infile.read(buf, fileSize); 
    infile.close();

    // outputSize();

    union tcpdump::item item;
    int offset = 24;
    // memcpy(item.data, buf+offset, 400);
    // tcpdump::testUdpFrame(item);

    char outBuf[1024];
    long long outLineNum = 0;
    union tcpdump::canMsg msg;
    int size;

    ofstream outfile; 
    outfile.open("data.csv", ios::out); 
    // cout << argv[0] << " reading from the file, argc = " << argc << endl; 

    int leastHeaderSize = 22;
    offset = 24;
    int pktLength = 0;
    for (offset=24; offset<(fileSize-leastHeaderSize); )
    {
        // 24 bytes header, catch 22 bytes first
        memcpy(item.data, buf + offset, leastHeaderSize);
        pktLength = item.pkt.outSize + 16;
        if ((pktLength + offset) > fileSize)
        {
            break;
        }
        memcpy(item.data, buf + offset, pktLength);
        if(memcmp(item.pkt.udp.frame.macDst, DstMacSelected, 6) == 0)
        {
            int payloadLength = changeEndian16(item.pkt.udp.frame.length) - 8;
            cout << "payload length : " << payloadLength << endl;

            if(payloadLength >= CanetPacketLength){
                int packetNum = payloadLength/CanetPacketLength;

                for (int i=0; i<packetNum; i++)
                {
                    memset(msg.data, 0, CanetPacketLength);
                    memcpy(msg.data, 
                        item.pkt.udp.frame.data + i*CanetPacketLength, 
                        CanetPacketLength);
                    size = sprintf(outBuf,
                            "%d,%d,%d,0x%04X\n",
                            item.pkt.sec, item.pkt.usec, msg.msg.DLC, changeEndian32(msg.msg.ID));
                    outfile.write(outBuf, size); 
                    outLineNum ++; 
                }
            }
        }
        offset += pktLength;
    }


    outfile.close();
    cout << "out line : " << outLineNum << endl;
    delete []buf;
    return 0;
}
