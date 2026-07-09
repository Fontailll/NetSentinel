#include "win_firewall.h"
#include <windows.h>
#include <oleauto.h>
#include <netfw.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

WindowsFirewall::WindowsFirewall() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
        initialized_ = true;
    }
}

WindowsFirewall::~WindowsFirewall() {
    if (initialized_) {
        CoUninitialize();
    }
}

bool WindowsFirewall::initialize() {
    return initialized_;
}

static std::string bstr_to_str(const _bstr_t& bstr) {
    return std::string(static_cast<const char*>(bstr), bstr.length());
}

bool WindowsFirewall::block_ip(const std::string& ip) {
    if (!initialized_) return false;

    HRESULT hr;
    INetFwPolicy2* pPolicy = nullptr;
    INetFwRules* pRules = nullptr;
    INetFwRule* pRule = nullptr;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwPolicy2), (void**)&pPolicy);
    if (FAILED(hr)) return false;

    hr = pPolicy->get_Rules(&pRules);
    if (FAILED(hr)) { pPolicy->Release(); return false; }

    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwRule), (void**)&pRule);
    if (FAILED(hr)) { pRules->Release(); pPolicy->Release(); return false; }

    std::string name = "NetWatch Block " + ip;
    _bstr_t bstrName(name.c_str());
    _bstr_t bstrDesc = L"Blocked by NetWatch Network Incident Response Tool";
    _bstr_t bstrIP(ip.c_str());

    pRule->put_Name(bstrName);
    pRule->put_Description(bstrDesc);
    pRule->put_Direction(NET_FW_RULE_DIR_OUT);
    pRule->put_RemoteAddresses(bstrIP);
    pRule->put_Action(NET_FW_ACTION_BLOCK);
    pRule->put_Enabled(VARIANT_TRUE);

    hr = pRules->Add(pRule);
    if (FAILED(hr)) {
        pRule->Release(); pRules->Release(); pPolicy->Release();
        return false;
    }

    pRule->put_Direction(NET_FW_RULE_DIR_IN);
    hr = pRules->Add(pRule);

    pRule->Release();
    pRules->Release();
    pPolicy->Release();
    return SUCCEEDED(hr);
}

bool WindowsFirewall::unblock_ip(const std::string& ip) {
    if (!initialized_) return false;

    HRESULT hr;
    INetFwPolicy2* pPolicy = nullptr;
    INetFwRules* pRules = nullptr;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwPolicy2), (void**)&pPolicy);
    if (FAILED(hr)) return false;

    hr = pPolicy->get_Rules(&pRules);
    if (FAILED(hr)) { pPolicy->Release(); return false; }

    _bstr_t bstrOutName(("NetWatch Block " + ip).c_str());
    _bstr_t bstrInName(("NetWatch Block In " + ip).c_str());

    hr = pRules->Remove(bstrOutName);
    hr = pRules->Remove(bstrInName);

    pRules->Release();
    pPolicy->Release();
    return true;
}

bool WindowsFirewall::block_port(uint16_t port) {
    if (!initialized_) return false;

    HRESULT hr;
    INetFwPolicy2* pPolicy = nullptr;
    INetFwRules* pRules = nullptr;
    INetFwRule* pRule = nullptr;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwPolicy2), (void**)&pPolicy);
    if (FAILED(hr)) return false;

    hr = pPolicy->get_Rules(&pRules);
    if (FAILED(hr)) { pPolicy->Release(); return false; }

    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwRule), (void**)&pRule);
    if (FAILED(hr)) { pRules->Release(); pPolicy->Release(); return false; }

    std::string name = "NetWatch Block Port " + std::to_string(port);
    std::string port_str = std::to_string(port);
    _bstr_t bstrName(name.c_str());
    _bstr_t bstrDesc = L"Blocked by NetWatch";
    _bstr_t bstrPort(port_str.c_str());

    pRule->put_Name(bstrName);
    pRule->put_Description(bstrDesc);
    pRule->put_Direction(NET_FW_RULE_DIR_OUT);
    pRule->put_RemotePorts(bstrPort);
    pRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    pRule->put_Action(NET_FW_ACTION_BLOCK);
    pRule->put_Enabled(VARIANT_TRUE);

    hr = pRules->Add(pRule);

    pRule->Release();
    pRules->Release();
    pPolicy->Release();
    return SUCCEEDED(hr);
}

bool WindowsFirewall::list_rules(std::vector<std::string>& rules) {
    if (!initialized_) return false;

    HRESULT hr;
    INetFwPolicy2* pPolicy = nullptr;
    INetFwRules* pRules = nullptr;

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_ALL,
                          __uuidof(INetFwPolicy2), (void**)&pPolicy);
    if (FAILED(hr)) return false;

    hr = pPolicy->get_Rules(&pRules);
    if (FAILED(hr)) { pPolicy->Release(); return false; }

    IUnknown* pEnumUnk = nullptr;
    hr = pRules->get__NewEnum(&pEnumUnk);
    if (FAILED(hr) || !pEnumUnk) {
        pRules->Release(); pPolicy->Release();
        return false;
    }

    IEnumVARIANT* pEnum = nullptr;
    hr = pEnumUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
    pEnumUnk->Release();
    if (FAILED(hr) || !pEnum) {
        pRules->Release(); pPolicy->Release();
        return false;
    }

    VARIANT var;
    VariantInit(&var);
    while (pEnum->Next(1, &var, nullptr) == S_OK) {
        INetFwRule* pRule = nullptr;
        hr = V_UNKNOWN(&var)->QueryInterface(__uuidof(INetFwRule), (void**)&pRule);
        if (SUCCEEDED(hr) && pRule) {
            BSTR bstrName = nullptr;
            if (SUCCEEDED(pRule->get_Name(&bstrName)) && bstrName) {
                _bstr_t name(bstrName, false);
                rules.push_back(bstr_to_str(name));
            }
            pRule->Release();
        }
        VariantClear(&var);
    }

    pEnum->Release();
    pRules->Release();
    pPolicy->Release();
    return true;
}
