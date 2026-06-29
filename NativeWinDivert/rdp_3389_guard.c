#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

#define PROTECTED_RDP_PORT 3389
#define MAX_ALLOWED_IPS 4096
#define MAX_BLOCK_LOG_IPS 8192
#define MAX_PACKET_SIZE 0xFFFF
#define BLOCK_LOG_INTERVAL_MS 10000

static HANDLE g_divert = INVALID_HANDLE_VALUE;
static HANDLE g_stop_event = NULL;
static uint32_t g_allowed_ips[MAX_ALLOWED_IPS];
static size_t g_allowed_count = 0;
static uint32_t g_block_log_ips[MAX_BLOCK_LOG_IPS];
static DWORD g_block_log_ticks[MAX_BLOCK_LOG_IPS];
static uint32_t g_block_log_packet_counts[MAX_BLOCK_LOG_IPS];
static size_t g_block_log_count = 0;

static void PrintUsage(void)
{
    printf("RDP 3389 WinDivert Guard\n\n");
    printf("Usage:\n");
    printf("  rdp_3389_guard.exe --allow YOUR.IP.ADDR.HERE [--allow OTHER.IP] [--allow-file rdp_allowed_ips.txt]\n\n");
    printf("Examples:\n");
    printf("  rdp_3389_guard.exe --allow 1.2.3.4\n");
    printf("  rdp_3389_guard.exe --allow-file rdp_allowed_ips.txt\n\n");
    printf("Only allowlisted source IPs can reach inbound TCP/3389. All other inbound TCP/3389 packets are dropped.\n");
}

static bool ParseIPv4(const char *text, uint32_t *ip)
{
    struct in_addr address;

    if (text == NULL || ip == NULL)
    {
        return false;
    }

    if (InetPtonA(AF_INET, text, &address) != 1)
    {
        return false;
    }

    *ip = address.S_un.S_addr;
    return true;
}

static void PrintIPv4(uint32_t ip, char *buffer, size_t buffer_size)
{
    struct in_addr address;
    address.S_un.S_addr = ip;

    if (InetNtopA(AF_INET, &address, buffer, (DWORD)buffer_size) == NULL)
    {
        strncpy_s(buffer, buffer_size, "<invalid-ip>", _TRUNCATE);
    }
}

static bool AddAllowedIPText(const char *text)
{
    uint32_t ip;

    if (!ParseIPv4(text, &ip))
    {
        fprintf(stderr, "[WARN] Invalid allow IP ignored: %s\n", text == NULL ? "" : text);
        return false;
    }

    for (size_t i = 0; i < g_allowed_count; i++)
    {
        if (g_allowed_ips[i] == ip)
        {
            return true;
        }
    }

    if (g_allowed_count >= MAX_ALLOWED_IPS)
    {
        fprintf(stderr, "[WARN] Allowlist is full, ignored: %s\n", text);
        return false;
    }

    g_allowed_ips[g_allowed_count++] = ip;
    return true;
}

static void TrimLine(char *line)
{
    char *start = line;
    char *end;

    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
    {
        start++;
    }

    if (start != line)
    {
        memmove(line, start, strlen(start) + 1);
    }

    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
    {
        end--;
    }
    *end = '\0';
}

static bool LoadAllowFile(const char *path)
{
    FILE *file;
    char line[256];
    int loaded = 0;

    if (fopen_s(&file, path, "r") != 0 || file == NULL)
    {
        fprintf(stderr, "[ERROR] Could not open allow file: %s\n", path);
        return false;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *comment;

        TrimLine(line);
        comment = strchr(line, '#');
        if (comment != NULL)
        {
            *comment = '\0';
            TrimLine(line);
        }

        if (line[0] == '\0')
        {
            continue;
        }

        if (AddAllowedIPText(line))
        {
            loaded++;
        }
    }

    fclose(file);
    printf("[INFO] Loaded %d allowlist entries from %s\n", loaded, path);
    return true;
}

static bool IsAllowedIP(uint32_t ip)
{
    for (size_t i = 0; i < g_allowed_count; i++)
    {
        if (g_allowed_ips[i] == ip)
        {
            return true;
        }
    }

    return false;
}

static void LogBlockedIP(uint32_t ip)
{
    DWORD now = GetTickCount();
    char ip_text[64];

    for (size_t i = 0; i < g_block_log_count; i++)
    {
        if (g_block_log_ips[i] == ip)
        {
            if (g_block_log_packet_counts[i] < UINT32_MAX)
            {
                g_block_log_packet_counts[i]++;
            }

            if ((DWORD)(now - g_block_log_ticks[i]) >= BLOCK_LOG_INTERVAL_MS)
            {
                uint32_t count = g_block_log_packet_counts[i];
                g_block_log_ticks[i] = now;
                g_block_log_packet_counts[i] = 0;
                PrintIPv4(ip, ip_text, sizeof(ip_text));
                printf("[RDP-GUARD] blocked %u packets from %s to TCP/%d in last 10s\n", count, ip_text, PROTECTED_RDP_PORT);
                fflush(stdout);
            }
            return;
        }
    }

    if (g_block_log_count < MAX_BLOCK_LOG_IPS)
    {
        g_block_log_ips[g_block_log_count] = ip;
        g_block_log_ticks[g_block_log_count] = now;
        g_block_log_packet_counts[g_block_log_count] = 1;
        g_block_log_count++;
    }
}

static bool TryReadInboundTcp4(const unsigned char *packet, UINT packet_len, uint32_t *src_ip, uint16_t *dst_port)
{
    unsigned int ip_header_len;
    const unsigned char *tcp;

    if (packet_len < 40)
    {
        return false;
    }

    if ((packet[0] >> 4) != 4)
    {
        return false;
    }

    ip_header_len = (packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 20)
    {
        return false;
    }

    if (packet[9] != IPPROTO_TCP)
    {
        return false;
    }

    memcpy(src_ip, packet + 12, sizeof(*src_ip));
    tcp = packet + ip_header_len;
    *dst_port = (uint16_t)((tcp[2] << 8) | tcp[3]);
    return true;
}

static BOOL WINAPI ConsoleHandler(DWORD control_type)
{
    if (control_type == CTRL_C_EVENT ||
        control_type == CTRL_BREAK_EVENT ||
        control_type == CTRL_CLOSE_EVENT ||
        control_type == CTRL_SHUTDOWN_EVENT)
    {
        if (g_stop_event != NULL)
        {
            SetEvent(g_stop_event);
        }

        if (g_divert != INVALID_HANDLE_VALUE)
        {
            WinDivertShutdown(g_divert, WINDIVERT_SHUTDOWN_BOTH);
        }

        return TRUE;
    }

    return FALSE;
}

static bool ParseArgs(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--allow") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "[ERROR] --allow needs an IPv4 value.\n");
                return false;
            }

            AddAllowedIPText(argv[++i]);
        }
        else if (strcmp(argv[i], "--allow-file") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "[ERROR] --allow-file needs a file path.\n");
                return false;
            }

            if (!LoadAllowFile(argv[++i]))
            {
                return false;
            }
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "/?") == 0)
        {
            PrintUsage();
            return false;
        }
        else
        {
            fprintf(stderr, "[ERROR] Unknown argument: %s\n", argv[i]);
            return false;
        }
    }

    return true;
}

int main(int argc, char **argv)
{
    unsigned char packet[MAX_PACKET_SIZE];
    UINT packet_len = 0;
    WINDIVERT_ADDRESS address;
    const char *filter = "inbound and ip and tcp.DstPort == 3389";

    if (!ParseArgs(argc, argv))
    {
        return 1;
    }

    if (g_allowed_count == 0)
    {
        fprintf(stderr, "[ERROR] Allowlist is empty. Refusing to start to avoid locking you out of RDP.\n\n");
        PrintUsage();
        return 1;
    }

    g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL)
    {
        fprintf(stderr, "[ERROR] CreateEvent failed: %lu\n", GetLastError());
        return 1;
    }

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE))
    {
        fprintf(stderr, "[WARN] SetConsoleCtrlHandler failed: %lu\n", GetLastError());
    }

    printf("[INFO] Protecting inbound TCP/%d continuously with %zu allowed IP(s).\n", PROTECTED_RDP_PORT, g_allowed_count);
    printf("[INFO] Press CTRL+C to stop.\n");
    fflush(stdout);

    g_divert = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_divert == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "[ERROR] WinDivertOpen failed: %lu. Run as Administrator and check WinDivert files.\n", GetLastError());
        CloseHandle(g_stop_event);
        return 1;
    }

    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT)
    {
        uint32_t src_ip;
        uint16_t dst_port;
        bool should_drop = false;

        if (!WinDivertRecv(g_divert, packet, sizeof(packet), &packet_len, &address))
        {
            DWORD error = GetLastError();
            if (WaitForSingleObject(g_stop_event, 0) != WAIT_TIMEOUT)
            {
                break;
            }

            fprintf(stderr, "[WARN] WinDivertRecv failed: %lu\n", error);
            continue;
        }

        if (TryReadInboundTcp4(packet, packet_len, &src_ip, &dst_port) && dst_port == PROTECTED_RDP_PORT)
        {
            should_drop = !IsAllowedIP(src_ip);
            if (should_drop)
            {
                LogBlockedIP(src_ip);
            }
        }

        if (!should_drop)
        {
            WinDivertSend(g_divert, packet, packet_len, NULL, &address);
        }
    }

    printf("[INFO] Stopping RDP guard.\n");

    if (g_divert != INVALID_HANDLE_VALUE)
    {
        WinDivertClose(g_divert);
        g_divert = INVALID_HANDLE_VALUE;
    }

    if (g_stop_event != NULL)
    {
        CloseHandle(g_stop_event);
        g_stop_event = NULL;
    }

    return 0;
}
