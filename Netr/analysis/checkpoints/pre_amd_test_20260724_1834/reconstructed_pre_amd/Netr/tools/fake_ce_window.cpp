// fake_ce_window.cpp
// 假装是 Cheat Engine 的空壳窗口 - 测试反作弊 / FindWindow hook
//
// 编译:
//   cl /EHsc /W3 /O2 fake_ce_window.cpp /link user32.lib gdi32.lib
//   生成 fake_ce_window.exe
//
// 行为:
//   - 创建一个标题为 "Cheat Engine 7.5" 的窗口
//   - 窗口类名是 "CHEATENGINE"
//   - 反作弊 / 检测工具调 FindWindow("CHEATENGINE",NULL) 或
//     FindWindow(NULL,"Cheat Engine 7.5") 都能精准定位到这个窗口
//   - 用于验证 hook 是否真的把 FindWindowEx 挡了

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static const wchar_t* kClassName  = L"CHEATENGINE";
static const wchar_t* kWindowName = L"Cheat Engine 7.5";

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(0, 0, 0));

        wchar_t buf[256];
        swprintf_s(buf,
            L"假 CE 窗口 - 用于测试反作弊检测\n"
            L"类名: %s\n"
            L"标题: %s\n"
            L"PID:  %lu",
            kClassName, kWindowName, GetCurrentProcessId());

        DrawTextW(hdc, buf, -1, &rc,
                  DT_CENTER | DT_VCENTER | DT_NOCLIP);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int wWinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd;

    // 注册窗口类 — 类名故意写 "CHEATENGINE"
    WNDCLASSEXW wc = { 0 };
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    wc.hIcon         = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"RegisterClassEx 失败", L"错误", MB_ICONERROR);
        return 1;
    }

    // 创建窗口 — 标题写 "Cheat Engine 7.5"
    HWND hwnd = CreateWindowExW(
        0,
        kClassName,
        kWindowName,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        600, 300,
        NULL, NULL, hInstance, NULL);

    if (!hwnd) {
        MessageBoxW(NULL, L"CreateWindow 失败", L"错误", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nShow ? nShow : SW_SHOW);
    UpdateWindow(hwnd);

    // 控制台打印 PID 方便对照
    wchar_t hdr[256];
    swprintf_s(hdr,
        L"假 CE 窗口已创建\n"
        L"  类名:   %s\n"
        L"  标题:   %s\n"
        L"  PID:    %lu\n"
        L"  窗口句柄: 0x%p\n",
        kClassName, kWindowName,
        GetCurrentProcessId(), hwnd);
    OutputDebugStringW(hdr);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
