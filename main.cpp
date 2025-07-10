#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <winspool.h>
#include <winsnmp.h>
#include <snmp.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <regex>
#include <string>
#include <stdexcept>
#include <memory>

// Link libraries (MSVC only - MinGW uses CMake linking)
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wsnmp32.lib")
#pragma comment(lib, "winspool.lib")
#endif

// ---------- helpers ---------------------------------------------------------

struct Printer
{
    std::wstring name;
    std::wstring port;
    Printer(const wchar_t *n, const wchar_t *p)
        : name(n ? n : L""), port(p ? p : L"") {}
};

std::vector<Printer> enumPrinters()
{
    DWORD bytesNeeded = 0, printersReturned = 0;
    
    // First call to get buffer size
    EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
                  nullptr, 2, nullptr, 0, &bytesNeeded, &printersReturned);
    
    if (bytesNeeded == 0) {
        return std::vector<Printer>();
    }
    
    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
                       nullptr, 2, buffer.data(), bytesNeeded,
                       &bytesNeeded, &printersReturned)) {
        DWORD error = GetLastError();
        throw std::runtime_error("EnumPrinters failed with error: " + std::to_string(error));
    }

    auto *pi2 = reinterpret_cast<PRINTER_INFO_2W *>(buffer.data());
    std::vector<Printer> list;
    for (DWORD i = 0; i < printersReturned; ++i) {
        list.emplace_back(pi2[i].pPrinterName, pi2[i].pPortName);
    }
    return list;
}

std::string wideToUtf8(const std::wstring &w)
{
    if (w.empty()) return std::string();
    
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return std::string();
    
    std::string s(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), sz, nullptr, nullptr);
    return s;
}

std::string extractIp(const std::wstring &port)
{
    // Handles: "IP_192.168.1.15", "192.168.1.15", "hpbf3e4f (HP Standard TCP/IP Port)"
    std::wregex ip(L"(\\d{1,3}(?:\\.\\d{1,3}){3})");
    std::wsmatch m;
    if (std::regex_search(port, m, ip)) {
        return wideToUtf8(m.str(1));
    }
    throw std::runtime_error("Could not parse IP address from port name: " + wideToUtf8(port));
}

// SNMP utilities -------------------------------------------------------------

class SnmpSession
{
public:
    SnmpSession(const std::string &ip, const std::string &community = "public")
        : session(SNMPAPI_FAILURE), entity(SNMPAPI_FAILURE), context(SNMPAPI_FAILURE)
    {
        smiUINT32 major, minor, level, translateMode, retransmitMode;
        SNMPAPI_STATUS status = SnmpStartup(&major, &minor, &level, &translateMode, &retransmitMode);
        if (status != SNMPAPI_SUCCESS) {
            throw std::runtime_error("SnmpStartup failed with status: " + std::to_string(status));
        }

        session = SnmpCreateSession(0, 0, nullptr, nullptr);
        if (session == SNMPAPI_FAILURE) {
            SnmpCleanup();
            throw std::runtime_error("SnmpCreateSession failed");
        }

        entity = SnmpStrToEntity(session, const_cast<char*>(ip.c_str()));
        if (entity == SNMPAPI_FAILURE) {
            SnmpClose(session);
            SnmpCleanup();
            throw std::runtime_error("SnmpStrToEntity failed for IP: " + ip);
        }

        // Create community string
        smiOCTETS communityOctets;
        communityOctets.len = static_cast<smiUINT32>(community.length());
        communityOctets.ptr = reinterpret_cast<smiLPBYTE>(const_cast<char*>(community.c_str()));
        
        context = SnmpStrToContext(session, &communityOctets);
        if (context == SNMPAPI_FAILURE) {
            SnmpClose(session);
            SnmpCleanup();
            throw std::runtime_error("SnmpStrToContext failed");
        }
    }

    ~SnmpSession()
    {
        if (context != SNMPAPI_FAILURE) {
            SnmpFreeContext(context);
        }
        if (entity != SNMPAPI_FAILURE) {
            SnmpFreeEntity(entity);
        }
        if (session != SNMPAPI_FAILURE) {
            SnmpClose(session);
        }
        SnmpCleanup();
    }

    // Get integer value from a scalar OID
    int getInt(const std::vector<UINT> &oidVec)
    {
        // Create VBL (Variable Binding List)
        HSNMP_VBL vbl = SnmpCreateVbl(session, nullptr, nullptr);
        if (vbl == SNMPAPI_FAILURE) {
            return -1;
        }

        // Create OID
        smiOID oid;
        oid.len = static_cast<smiUINT32>(oidVec.size());
        std::vector<smiUINT32> oidData(oidVec.begin(), oidVec.end());
        oid.ptr = oidData.data();

        // Add variable to VBL
        if (SnmpSetVb(vbl, 1, &oid, nullptr) == SNMPAPI_FAILURE) {
            SnmpFreeVbl(vbl);
            return -1;
        }

        // Create PDU
        HSNMP_PDU pdu = SnmpCreatePdu(session, SNMP_PDU_GET, 0, 0, 0, vbl);
        if (pdu == SNMPAPI_FAILURE) {
            SnmpFreeVbl(vbl);
            return -1;
        }

        // Create source entity for sending
        HSNMP_ENTITY srcEntity = SnmpStrToEntity(session, "");
        if (srcEntity == SNMPAPI_FAILURE) {
            SnmpFreePdu(pdu);
            SnmpFreeVbl(vbl);
            return -1;
        }

        int result = -1;
        
        // Send request
        if (SnmpSendMsg(session, srcEntity, entity, context, pdu) == SNMPAPI_SUCCESS) {
            HSNMP_PDU reply = nullptr;
            HSNMP_ENTITY srcReply = nullptr, dstReply = nullptr;
            HSNMP_CONTEXT ctxReply = nullptr;
            
            // Wait for response with timeout
            if (SnmpRecvMsg(session, &srcReply, &dstReply, &ctxReply, &reply) == SNMPAPI_SUCCESS) {
                // Get the VBL from the reply
                HSNMP_VBL replyVbl = nullptr;
                smiINT pduType, errorStatus, errorIndex;
                smiINT32 requestId;
                
                if (SnmpGetPduData(reply, &pduType, &requestId, &errorStatus, &errorIndex, &replyVbl) == SNMPAPI_SUCCESS) {
                    if (errorStatus == SNMP_ERROR_NOERROR) {
                        smiOID replyOid;
                        smiVALUE replyValue;
                        
                        if (SnmpGetVb(replyVbl, 1, &replyOid, &replyValue) == SNMPAPI_SUCCESS) {
                            switch (replyValue.syntax) {
                                case SNMP_SYNTAX_INT:
                                    result = static_cast<int>(replyValue.value.sNumber);
                                    break;
                                case SNMP_SYNTAX_GAUGE32:
                                case SNMP_SYNTAX_CNTR32:
                                case SNMP_SYNTAX_TIMETICKS:
                                    result = static_cast<int>(replyValue.value.uNumber);
                                    break;
                                default:
                                    // Unsupported type
                                    break;
                            }
                        }
                    }
                }
                SnmpFreePdu(reply);
            }
        }
        
        SnmpFreeEntity(srcEntity);
        SnmpFreePdu(pdu);
        SnmpFreeVbl(vbl);
        return result;
    }

    // Get string value from OID
    std::string getString(const std::vector<UINT> &oidVec)
    {
        HSNMP_VBL vbl = SnmpCreateVbl(session, nullptr, nullptr);
        if (vbl == SNMPAPI_FAILURE) {
            return "";
        }

        smiOID oid;
        oid.len = static_cast<smiUINT32>(oidVec.size());
        std::vector<smiUINT32> oidData(oidVec.begin(), oidVec.end());
        oid.ptr = oidData.data();

        if (SnmpSetVb(vbl, 1, &oid, nullptr) == SNMPAPI_FAILURE) {
            SnmpFreeVbl(vbl);
            return "";
        }

        HSNMP_PDU pdu = SnmpCreatePdu(session, SNMP_PDU_GET, 0, 0, 0, vbl);
        if (pdu == SNMPAPI_FAILURE) {
            SnmpFreeVbl(vbl);
            return "";
        }

        HSNMP_ENTITY srcEntity = SnmpStrToEntity(session, "");
        if (srcEntity == SNMPAPI_FAILURE) {
            SnmpFreePdu(pdu);
            SnmpFreeVbl(vbl);
            return "";
        }

        std::string result;
        
        if (SnmpSendMsg(session, srcEntity, entity, context, pdu) == SNMPAPI_SUCCESS) {
            HSNMP_PDU reply = nullptr;
            HSNMP_ENTITY srcReply = nullptr, dstReply = nullptr;
            HSNMP_CONTEXT ctxReply = nullptr;
            
            if (SnmpRecvMsg(session, &srcReply, &dstReply, &ctxReply, &reply) == SNMPAPI_SUCCESS) {
                HSNMP_VBL replyVbl = nullptr;
                smiINT pduType, errorStatus, errorIndex;
                smiINT32 requestId;
                
                if (SnmpGetPduData(reply, &pduType, &requestId, &errorStatus, &errorIndex, &replyVbl) == SNMPAPI_SUCCESS) {
                    if (errorStatus == SNMP_ERROR_NOERROR) {
                        smiOID replyOid;
                        smiVALUE replyValue;
                        
                        if (SnmpGetVb(replyVbl, 1, &replyOid, &replyValue) == SNMPAPI_SUCCESS) {
                            if (replyValue.syntax == SNMP_SYNTAX_OCTETS) {
                                result = std::string(reinterpret_cast<char*>(replyValue.value.string.ptr), 
                                                   replyValue.value.string.len);
                            }
                        }
                    }
                }
                SnmpFreePdu(reply);
            }
        }
        
        SnmpFreeEntity(srcEntity);
        SnmpFreePdu(pdu);
        SnmpFreeVbl(vbl);
        return result;
    }

private:
    HSNMP_SESSION session;
    HSNMP_ENTITY entity;
    HSNMP_CONTEXT context;
};

// OID helpers ----------------------------------------------------------------

inline std::vector<UINT> makeOid(std::initializer_list<UINT> lst)
{
    return std::vector<UINT>(lst);
}

// Standard Printer-MIB (RFC 3805) OIDs
std::vector<UINT> prtMarkerSuppliesLevel(int i) { 
    return makeOid({1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 9, 1, static_cast<UINT>(i)}); 
}

std::vector<UINT> prtMarkerSuppliesMaxCap(int i) { 
    return makeOid({1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 8, 1, static_cast<UINT>(i)}); 
}

std::vector<UINT> prtMarkerColorantValue(int i) { 
    return makeOid({1, 3, 6, 1, 2, 1, 43, 12, 1, 1, 4, 1, static_cast<UINT>(i)}); 
}

std::vector<UINT> prtInputMediaName(int i) { 
    return makeOid({1, 3, 6, 1, 2, 1, 43, 8, 2, 1, 19, 1, static_cast<UINT>(i)}); 
}

std::vector<UINT> prtMarkerSuppliesDescription(int i) {
    return makeOid({1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 6, 1, static_cast<UINT>(i)});
}

// HP-private OIDs for DesignJet
std::vector<UINT> hpRoll1Remaining() { 
    return makeOid({1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 4, 1, 3, 3, 1, 11, 0}); 
}

std::vector<UINT> hpRoll2Remaining() { 
    return makeOid({1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 4, 1, 3, 3, 2, 11, 0}); 
}

// System info OIDs
std::vector<UINT> sysDescr() { 
    return makeOid({1, 3, 6, 1, 2, 1, 1, 1, 0}); 
}

std::vector<UINT> sysName() { 
    return makeOid({1, 3, 6, 1, 2, 1, 1, 5, 0}); 
}

// ---------------------------------------------------------------------------

std::string formatPercentage(int current, int maximum)
{
    if (maximum <= 0) return "Unknown";
    
    int percentage = static_cast<int>((static_cast<double>(current) / maximum) * 100);
    return std::to_string(percentage) + "%";
}

void printInkLevels(SnmpSession &snmp)
{
    std::cout << "\nInk / Print-head levels:\n";
    std::cout << "-------------------------\n";
    
    bool foundAny = false;
    for (int i = 1; i <= 12; ++i) { // Check up to 12 slots
        int maxCap = snmp.getInt(prtMarkerSuppliesMaxCap(i));
        int level = snmp.getInt(prtMarkerSuppliesLevel(i));
        
        if (maxCap > 0 && level >= 0) {
            std::string description = snmp.getString(prtMarkerSuppliesDescription(i));
            std::string colorant = snmp.getString(prtMarkerColorantValue(i));
            
            std::cout << "Slot " << std::setw(2) << i << ": ";
            if (!description.empty()) {
                std::cout << description << " ";
            }
            if (!colorant.empty()) {
                std::cout << "(" << colorant << ") ";
            }
            std::cout << "→ " << formatPercentage(level, maxCap) 
                      << " [" << level << "/" << maxCap << "]\n";
            foundAny = true;
        }
    }
    
    if (!foundAny) {
        std::cout << "No ink level information available\n";
    }
}

void printMediaInfo(SnmpSession &snmp)
{
    std::cout << "\nMedia (Input trays/rolls):\n";
    std::cout << "--------------------------\n";
    
    bool foundAny = false;
    for (int i = 1; i <= 5; ++i) { // Check up to 5 inputs
        std::string mediaName = snmp.getString(prtInputMediaName(i));
        if (!mediaName.empty()) {
            std::cout << "Input " << i << ": " << mediaName << "\n";
            foundAny = true;
        }
    }
    
    if (!foundAny) {
        std::cout << "No media information available\n";
    }
}

void printRollInfo(SnmpSession &snmp)
{
    std::cout << "\nRoll information (HP-specific):\n";
    std::cout << "-------------------------------\n";
    
    bool foundAny = false;
    
    // Roll 1
    int roll1 = snmp.getInt(hpRoll1Remaining());
    if (roll1 >= 0) {
        std::cout << "Roll 1 remaining: " << roll1 << " cm\n";
        foundAny = true;
    }
    
    // Roll 2
    int roll2 = snmp.getInt(hpRoll2Remaining());
    if (roll2 >= 0) {
        std::cout << "Roll 2 remaining: " << roll2 << " cm\n";
        foundAny = true;
    }
    
    if (!foundAny) {
        std::cout << "No roll information available (may not be HP DesignJet)\n";
    }
}

void printSystemInfo(SnmpSession &snmp)
{
    std::cout << "\nSystem information:\n";
    std::cout << "-------------------\n";
    
    std::string sysDesc = snmp.getString(sysDescr());
    std::string sysN = snmp.getString(sysName());
    
    if (!sysDesc.empty()) {
        std::cout << "Description: " << sysDesc << "\n";
    }
    if (!sysN.empty()) {
        std::cout << "Name: " << sysN << "\n";
    }
}

int main()
try
{
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    auto printers = enumPrinters();
    if (printers.empty()) {
        std::cerr << "No printers found\n";
        WSACleanup();
        return 1;
    }

    std::wcout << L"Installed printers:\n";
    for (size_t i = 0; i < printers.size(); ++i) {
        std::wcout << std::setw(2) << i << L": " << printers[i].name
                   << L"  [" << printers[i].port << L"]\n";
    }

    std::wcout << L"\nSelect a printer #: ";
    size_t choice;
    std::wcin >> choice;
    if (choice >= printers.size()) {
        std::wcout << L"Invalid selection\n";
        WSACleanup();
        return 0;
    }

    std::string ip;
    try {
        ip = extractIp(printers[choice].port);
    } catch (const std::exception& e) {
        std::cerr << "Error extracting IP: " << e.what() << "\n";
        WSACleanup();
        return 1;
    }

    std::cout << "\nQuerying " << wideToUtf8(printers[choice].name) << " at " << ip << "...\n";

    try {
        SnmpSession snmp(ip);
        
        printSystemInfo(snmp);
        printInkLevels(snmp);
        printMediaInfo(snmp);
        printRollInfo(snmp);
        
    } catch (const std::exception& e) {
        std::cerr << "SNMP Error: " << e.what() << "\n";
        WSACleanup();
        return 1;
    }

    std::cout << "\nQuery completed.\n";
    WSACleanup();
    return 0;
}
catch (const std::exception &ex)
{
    std::cerr << "Error: " << ex.what() << "\n";
    WSACleanup();
    return 1;
}