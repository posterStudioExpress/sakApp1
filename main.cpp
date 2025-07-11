#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>

#include <winsock2.h>
#include <snmp.h>
#include <mgmtapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Snmpapi.lib")
#pragma comment(lib, "Mgmtapi.lib")

// Get an integer OID over SNMP v1/v2c
long snmpGetInt(const char* ip,
                const char* community,
                const char* oidStr)
{
    AsnObjectIdentifier oid;
    if (!SnmpMgrStrToOid((LPSTR)oidStr, &oid))
        throw std::runtime_error("SnmpMgrStrToOid failed");

    // timeout=2000ms, retries=1
    HSNMP_MGR_SESSION sess = SnmpMgrOpen(
        (LPSTR)ip, (LPSTR)community, 2000, 1);
    if (!sess)
        throw std::runtime_error("SnmpMgrOpen failed");

    RFC1157VarBind vb{};
    vb.name         = oid;
    vb.value.asnType = ASN_NULL;

    RFC1157VarBindList list;
    list.list = &vb;
    list.len  = 1;

    AsnInteger errStat, errIdx;
    if (!SnmpMgrRequest(
            sess,
            ASN_RFC1157_GETREQUEST,
            &list,
            &errStat,
            &errIdx))
    {
        SnmpMgrClose(sess);
        throw std::runtime_error("SnmpMgrRequest failed");
    }
    SnmpMgrClose(sess);

    if (errStat != SNMP_ERRORSTATUS_NOERROR)
        throw std::runtime_error("SNMP error status");
    if (vb.value.asnType != ASN_INTEGER)
        throw std::runtime_error("Unexpected SNMP type");

    long value = vb.value.asnValue.number;
    SnmpUtilOidFree(&oid);
    return value;
}

// Send raw bytes to printer:9100
void sendPrintJob(const char* ip, const char* filepath)
{
    std::ifstream in(filepath, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open print file");

    std::vector<char> buffer(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    );

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
        throw std::runtime_error("WSAStartup failed");

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        throw std::runtime_error("Socket creation failed");

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(9100);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        throw std::runtime_error("Connect to printer failed");
    }

    int sent = ::send(
        sock,
        buffer.data(),
        static_cast<int>(buffer.size()),
        0
    );
    closesocket(sock);
    WSACleanup();

    if (sent == SOCKET_ERROR)
        throw std::runtime_error("Send failed");
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <printer_ip> <file_to_print>\n";
        return 1;
    }

    const char* ip       = argv[1];
    const char* filePath = argv[2];
    const char* comm     = "public";

    try {
        std::cout << "[SNMP] Toner level: "
                  << snmpGetInt(ip, comm,
                     "1.3.6.1.2.1.43.11.1.1.6.1.1")
                  << "%\n";

        std::cout << "[SNMP] Tray count:  "
                  << snmpGetInt(ip, comm,
                     "1.3.6.1.2.1.43.8.2.1.18.1.1")
                  << "\n";

        std::cout << "[SNMP] Error state: "
                  << snmpGetInt(ip, comm,
                     "1.3.6.1.2.1.25.3.5.1.2.1")
                  << "\n\n";

        std::cout << "Sending print job...\n";
        sendPrintJob(ip, filePath);
        std::cout << "Print job sent successfully.\n";
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 2;
    }

    return 0;
}
