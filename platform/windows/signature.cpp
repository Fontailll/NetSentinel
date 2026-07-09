#include "signature.h"
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <memory>
#include <string>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

std::optional<SignatureInfo> verify_signature(const std::string& path) {
    if (path.empty()) return std::nullopt;

    SignatureInfo info;
    info.signed_binary = false;

    std::wstring wpath(path.begin(), path.end());
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath.c_str();

    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &file_info;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &action, &wtd);

    if (status == ERROR_SUCCESS) {
        info.signed_binary = true;

        HCERTSTORE hStore = nullptr;
        HCRYPTMSG hMsg = nullptr;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
                &hStore, &hMsg, nullptr)) {

            DWORD size = 0;
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &size)) {
                auto info_buf = std::unique_ptr<BYTE[]>(new BYTE[size]);
                auto signer = reinterpret_cast<PCMSG_SIGNER_INFO>(info_buf.get());
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, info_buf.get(), &size)) {
                    CERT_INFO cert_info = {};
                    cert_info.Issuer = signer->Issuer;
                    cert_info.SerialNumber = signer->SerialNumber;

                    PCCERT_CONTEXT cert = CertFindCertificateInStore(hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                        CERT_FIND_SUBJECT_CERT, &cert_info, nullptr);
                    if (cert) {
                        wchar_t publisher[256] = {};
                        DWORD pub_size = sizeof(publisher);
                        if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0, nullptr, publisher, pub_size)) {
                            int len = WideCharToMultiByte(CP_UTF8, 0, publisher, -1,
                                nullptr, 0, nullptr, nullptr);
                            if (len > 0) {
                                info.publisher.resize(len - 1);
                                WideCharToMultiByte(CP_UTF8, 0, publisher, -1,
                                    &info.publisher[0], len, nullptr, nullptr);
                            }
                        }
                        CertFreeCertificateContext(cert);
                    }
                }
            }

            if (hMsg) CryptMsgClose(hMsg);
            if (hStore) CertCloseStore(hStore, 0);
        }
    }

    return info;
}
