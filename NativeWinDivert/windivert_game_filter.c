#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "windivert.h"

#define MAX_ALLOWED_IPS 4096
#define MAX_PACKET_SIZE 0xFFFF

typedef void (__cdecl *blocked_ip_log_callback_t)(uint32_t ip, uint16_t port, uint32_t blocked_packet_count);

static CRITICAL_SECTION g_lock;
static HANDLE g_thread = NULL;
static HANDLE g_stop_event = NULL;
static HANDLE g_divert = INVALID_HANDLE_VALUE;
static uint32_t g_allowed_ips[MAX_ALLOWED_IPS];
static size_t g_allowed_count = 0;
static uint16_t g_protected_udp_port = 0;
static blocked_ip_log_callback_t g_blocked_ip_log_callback = NULL;
static volatile LONG g_running = 0;
static volatile LONG g_initialized = 0;

static void EnsureInitialized(void)
{
    if (InterlockedCompareExchange(&g_initialized, 1, 0) == 0)
    {
        InitializeCriticalSection(&g_lock);
        g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    }
}

static bool IsAllowedIP(uint32_t ip)
{
    bool allowed = false;

    EnterCriticalSection(&g_lock);
    for (size_t i = 0; i < g_allowed_count; i++)
    {
        if (g_allowed_ips[i] == ip)
        {
            allowed = true;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);

    return allowed;
}

static uint16_t GetProtectedUdpPort(void)
{
    uint16_t port;

    EnterCriticalSection(&g_lock);
    port = g_protected_udp_port;
    LeaveCriticalSection(&g_lock);

    return port;
}

static void LogBlockedIP(uint32_t ip, uint16_t port)
{
    blocked_ip_log_callback_t callback;

    EnterCriticalSection(&g_lock);
    callback = g_blocked_ip_log_callback;
    LeaveCriticalSection(&g_lock);

    if (callback != NULL)
    {
        callback(ip, port, 1);
    }
}

static bool TryReadInboundUdp4(const unsigned char *packet, UINT packet_len, uint32_t *src_ip, uint16_t *dst_port)
{
    unsigned int ip_header_len;
    const unsigned char *udp;

    if (packet_len < 28)
    {
        return false;
    }

    if ((packet[0] >> 4) != 4)
    {
        return false;
    }

    ip_header_len = (packet[0] & 0x0F) * 4;
    if (ip_header_len < 20 || packet_len < ip_header_len + 8)
    {
        return false;
    }

    if (packet[9] != IPPROTO_UDP)
    {
        return false;
    }

    memcpy(src_ip, packet + 12, sizeof(*src_ip));
    udp = packet + ip_header_len;
    *dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
    return true;
}

static DWORD WINAPI FilterThread(LPVOID parameter)
{
    unsigned char packet[MAX_PACKET_SIZE];
    UINT packet_len = 0;
    WINDIVERT_ADDRESS address;

    (void)parameter;

    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT)
    {
        bool should_drop = false;
        uint16_t protected_port;
        uint32_t src_ip;
        uint16_t dst_port;

        if (!WinDivertRecv(g_divert, packet, sizeof(packet), &packet_len, &address))
        {
            continue;
        }

        if (TryReadInboundUdp4(packet, packet_len, &src_ip, &dst_port))
        {
            protected_port = GetProtectedUdpPort();
            if (protected_port != 0 && dst_port == protected_port)
            {
                should_drop = !IsAllowedIP(src_ip);
                if (should_drop)
                {
                    LogBlockedIP(src_ip, dst_port);
                }
            }
        }

        if (!should_drop)
        {
            WinDivertSend(g_divert, packet, packet_len, NULL, &address);
        }
    }

    WinDivertClose(g_divert);
    g_divert = INVALID_HANDLE_VALUE;
    InterlockedExchange(&g_running, 0);
    return 0;
}

__declspec(dllexport) void __cdecl SetProtectedUdpPort(uint16_t port)
{
    EnsureInitialized();

    EnterCriticalSection(&g_lock);
    g_protected_udp_port = port;
    LeaveCriticalSection(&g_lock);
}

__declspec(dllexport) void __cdecl SetBlockedIPLogCallback(blocked_ip_log_callback_t callback)
{
    EnsureInitialized();

    EnterCriticalSection(&g_lock);
    g_blocked_ip_log_callback = callback;
    LeaveCriticalSection(&g_lock);
}

__declspec(dllexport) int __cdecl StartFilter(void)
{
    const char *filter = "inbound and ip and udp";

    EnsureInitialized();

    if (InterlockedCompareExchange(&g_running, 1, 0) != 0)
    {
        return 1;
    }

    ResetEvent(g_stop_event);
    g_divert = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_divert == INVALID_HANDLE_VALUE)
    {
        InterlockedExchange(&g_running, 0);
        return 0;
    }

    g_thread = CreateThread(NULL, 0, FilterThread, NULL, 0, NULL);
    if (g_thread == NULL)
    {
        WinDivertClose(g_divert);
        g_divert = INVALID_HANDLE_VALUE;
        InterlockedExchange(&g_running, 0);
        return 0;
    }

    return 1;
}

__declspec(dllexport) void __cdecl StopFilter(void)
{
    EnsureInitialized();

    if (InterlockedCompareExchange(&g_running, 0, 1) != 1)
    {
        return;
    }

    SetEvent(g_stop_event);

    if (g_divert != INVALID_HANDLE_VALUE)
    {
        WinDivertShutdown(g_divert, WINDIVERT_SHUTDOWN_BOTH);
    }

    if (g_thread != NULL)
    {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
}

__declspec(dllexport) void __cdecl AddAllowedIP(uint32_t ip)
{
    EnsureInitialized();

    EnterCriticalSection(&g_lock);
    for (size_t i = 0; i < g_allowed_count; i++)
    {
        if (g_allowed_ips[i] == ip)
        {
            LeaveCriticalSection(&g_lock);
            return;
        }
    }

    if (g_allowed_count < MAX_ALLOWED_IPS)
    {
        g_allowed_ips[g_allowed_count++] = ip;
    }
    LeaveCriticalSection(&g_lock);
}

__declspec(dllexport) void __cdecl RemoveAllowedIP(uint32_t ip)
{
    EnsureInitialized();

    EnterCriticalSection(&g_lock);
    for (size_t i = 0; i < g_allowed_count; i++)
    {
        if (g_allowed_ips[i] == ip)
        {
            g_allowed_ips[i] = g_allowed_ips[g_allowed_count - 1];
            g_allowed_count--;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH)
    {
        EnsureInitialized();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        StopFilter();
    }

    return TRUE;
}
