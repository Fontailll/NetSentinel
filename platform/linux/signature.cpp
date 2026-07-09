#include "signature.h"

std::optional<SignatureInfo> verify_signature(const std::string& path) {
    (void)path;
    SignatureInfo info;
    info.signed_binary = true;
    info.publisher = "Linux";
    return info;
}
