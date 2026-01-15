#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif

#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)

namespace nt
{
    enum SYSINFO : ULONG { HandleInfo = 16 };
    enum OBJINFO : ULONG { ObjName = 1, ObjType = 2 };

    struct USTR {
        USHORT len;
        USHORT max;
        PWSTR  buf;
    };

    struct OBJTYPE {
        USTR name;
    };

    struct SHANDLE {
        ULONG pid;
        BYTE  type;
        BYTE  flags;
        USHORT handle;
        PVOID object;
        ACCESS_MASK access;
    };

    struct SHANDLEINFO {
        ULONG count;
        SHANDLE list[1];
    };

    using QSI = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    using QO = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using DUP = LONG(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
}

static std::string ws2s(const wchar_t* w)
{
    if (!w) return {};
    int sz = WideCharToMultiByte(CP_ACP, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string r(sz, 0);
    WideCharToMultiByte(CP_ACP, 0, w, -1, &r[0], sz, nullptr, nullptr);
    r.pop_back();
    return r;
}

static bool ieq(std::string a, std::string b)
{
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a == b;
}

static std::vector<DWORD> collect_targets()
{
    std::vector<DWORD> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{ sizeof(pe) };

    if (Process32FirstW(snap, &pe)) {
        do {
            if (ieq(ws2s(pe.szExeFile), "robloxplayerbeta.exe"))
                out.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static void neutralize(
    DWORD pid,
    nt::QSI qsi,
    nt::QO qo,
    nt::DUP dup)
{
    ULONG cap = 0x20000;
    std::vector<char> buf;
    LONG st;

    do {
        buf.resize(cap);
        st = qsi(nt::HandleInfo, buf.data(), cap, &cap);
        cap *= 2;
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) return;

    auto info = reinterpret_cast<nt::SHANDLEINFO*>(buf.data());
    HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) return;

    const std::string needle =
        "\\Sessions\\1\\BaseNamedObjects\\ROBLOX_singletonEvent";

    for (ULONG i = 0; i < info->count; ++i)
    {
        auto& h = info->list[i];
        if (h.pid != pid) continue;

        HANDLE tmp{};
        if (!DuplicateHandle(proc, (HANDLE)(uintptr_t)h.handle,
            GetCurrentProcess(), &tmp, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        BYTE tbuf[512]; ULONG ret{};
        if (NT_SUCCESS(qo(tmp, nt::ObjType, tbuf, sizeof(tbuf), &ret)))
        {
            auto ti = reinterpret_cast<nt::OBJTYPE*>(tbuf);
            if (ws2s(ti->name.buf) == "Event")
            {
                BYTE nbuf[2048];
                if (NT_SUCCESS(qo(tmp, nt::ObjName, nbuf, sizeof(nbuf), &ret)))
                {
                    auto un = reinterpret_cast<nt::USTR*>(nbuf);
                    if (ws2s(un->buf) == needle)
                    {
                        dup(proc, (HANDLE)(uintptr_t)h.handle,
                            nullptr, nullptr, 0, 0,
                            DUPLICATE_CLOSE_SOURCE);

                        std::cout << "[+] cleaned pid " << pid << "\n";
                    }
                }
            }
        }
        CloseHandle(tmp);
    }
    CloseHandle(proc);
}

HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);

void color(WORD c) {
    SetConsoleTextAttribute(hCon, c);
}

void clear() {
    COORD c{ 0,0 };
    DWORD n;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hCon, &csbi);
    FillConsoleOutputCharacterA(
        hCon, ' ',
        csbi.dwSize.X * csbi.dwSize.Y,
        c, &n
    );
    SetConsoleCursorPosition(hCon, c);
}

void center(const std::string& s, int w = 60) {
    int pad = (w - (int)s.size()) / 2;
    if (pad < 0) pad = 0;
    std::cout << std::string(pad, ' ') << s << "\n";
}

void draw_header()
{
    color(11);
    std::cout <<
        "+--------------------------------------------------+\n";
    std::cout <<
        "|                                                  |\n";
    center("ROBLOX INSTANCE MANAGER", 50);
    std::cout <<
        "|                                                  |\n";
    std::cout <<
        "+--------------------------------------------------+\n";
    color(7);
}

void draw_status(int processes, int killed)
{
    color(10);
    std::cout << "\n  STATUS: ACTIVE\n";
    color(7);

    std::cout << "  Roblox instances : " << processes << "\n";
    std::cout << "  Events closed    : " << killed << "\n";
    std::cout << "  Refresh interval : 1000 ms\n";
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    auto qsi = (nt::QSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    auto qo = (nt::QO)GetProcAddress(ntdll, "NtQueryObject");
    auto dup = (nt::DUP)GetProcAddress(ntdll, "NtDuplicateObject");
    if (!qsi || !qo || !dup) return 0;

    int totalKilled = 0;

    while (true)
    {
        clear();
        draw_header();

        auto targets = collect_targets();

        for (auto pid : targets)
        {
            int before = totalKilled;
            neutralize(pid, qsi, qo, dup);
            if (before != totalKilled)
                totalKilled++;
        }

        draw_status((int)targets.size(), totalKilled);

        color(8);
        std::cout << "\n  Press CTRL+C to exit\n";
        color(7);

        Sleep(1000);
    }
}
