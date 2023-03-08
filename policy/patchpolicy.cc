#include <algorithm>
#include <cstring>
#include <openssl/evp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include "device_management_backend.pb.h"
#include "chrome_device_policy.pb.h"
#include "boringssl/install/include/openssl/evp.h"
#include "boringssl/install/include/openssl/bn.h"
#include "boringssl/install/include/openssl/bytestring.h"
#include "boringssl/install/include/openssl/base.h"
#include "boringssl/install/include/openssl/mem.h"
#include "boringssl/install/include/openssl/rsa.h"

using namespace std;

// holy shit, we actually have device policy editing, holy fucking bingle what?! :3
// rip ultrablue o7

/*
 * OK breakthrough at like 1am, i need to generate a new key + sign the blob in this code
 * the --disable-policy-key-verification only disables verifying my custom key not verification
 * altogether
 * - r58 (i have like 5 tabs of code search open) (and a few tabs of gitiles) (and chromeenterprise.google/policies)
 */

/*
 * r58 update 2: i need to either compile all of chromium and extract the crypto lib or rewrite the parts of the
 *               lib that i need (it's the next day)
 */

/*
 * r58 update 3: i stopped working on this for a while and seem to have another breakthrough!!! woow!!
 *               i also need to write to owner.key lol
 */


// Signing key test data in DER-encoded PKCS8 format.
const uint8_t kSigningKey[] = {
    0x30, 0x82, 0x01, 0x55, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
    0x01, 0x3f, 0x30, 0x82, 0x01, 0x3b, 0x02, 0x01, 0x00, 0x02, 0x41, 0x00,
    0xd9, 0xcd, 0xca, 0xcd, 0xc3, 0xea, 0xbe, 0x72, 0x79, 0x1c, 0x29, 0x37,
    0x39, 0x99, 0x1f, 0xd4, 0xb3, 0x0e, 0xf0, 0x7b, 0x78, 0x77, 0x0e, 0x05,
    0x3b, 0x65, 0x34, 0x12, 0x62, 0xaf, 0xa6, 0x8d, 0x33, 0xce, 0x78, 0xf8,
    0x47, 0x05, 0x1d, 0x98, 0xaa, 0x1b, 0x1f, 0x50, 0x05, 0x5b, 0x3c, 0x19,
    0x3f, 0x80, 0x83, 0x63, 0x63, 0x3a, 0xec, 0xcb, 0x2e, 0x90, 0x4f, 0xf5,
    0x26, 0x76, 0xf1, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x40, 0x64,
    0x29, 0xc2, 0xd9, 0x6b, 0xfe, 0xf9, 0x84, 0x75, 0x73, 0xe0, 0xf4, 0x77,
    0xb5, 0x96, 0xb0, 0xdf, 0x83, 0xc0, 0x4e, 0x57, 0xf1, 0x10, 0x6e, 0x91,
    0x89, 0x12, 0x30, 0x5e, 0x57, 0xff, 0x14, 0x59, 0x5f, 0x18, 0x86, 0x4e,
    0x4b, 0x17, 0x56, 0xfc, 0x8d, 0x40, 0xdd, 0x74, 0x65, 0xd3, 0xff, 0x67,
    0x64, 0xcb, 0x9c, 0xb4, 0x14, 0x8a, 0x06, 0xb7, 0x13, 0x45, 0x94, 0x16,
    0x7d, 0x3f, 0xe1, 0x02, 0x21, 0x00, 0xf6, 0x0f, 0x31, 0x6d, 0x06, 0xcc,
    0x3b, 0xa0, 0x44, 0x1f, 0xf5, 0xc2, 0x45, 0x2b, 0x10, 0x6c, 0xf9, 0x6f,
    0x8f, 0x87, 0x3d, 0xc0, 0x3b, 0x55, 0x13, 0x37, 0x80, 0xcd, 0x9f, 0xe1,
    0xb7, 0xd9, 0x02, 0x21, 0x00, 0xe2, 0x9a, 0x5f, 0xbf, 0x95, 0x74, 0xb5,
    0x7a, 0x6a, 0xa6, 0x97, 0xbd, 0x75, 0x8c, 0x97, 0x18, 0x24, 0xd6, 0x09,
    0xcd, 0xdc, 0xb5, 0x94, 0xbf, 0xe2, 0x78, 0xaa, 0x20, 0x47, 0x9f, 0x68,
    0x5d, 0x02, 0x21, 0x00, 0xaf, 0x8f, 0x97, 0x8c, 0x5a, 0xd5, 0x4d, 0x95,
    0xc4, 0x05, 0xa9, 0xab, 0xba, 0xfe, 0x46, 0xf1, 0xf9, 0xe7, 0x07, 0x59,
    0x4f, 0x4d, 0xe1, 0x07, 0x8a, 0x76, 0x87, 0x88, 0x2f, 0x13, 0x35, 0xc1,
    0x02, 0x20, 0x24, 0xc3, 0xd9, 0x2f, 0x13, 0x47, 0x99, 0x3e, 0x20, 0x59,
    0xa1, 0x1a, 0xeb, 0x1c, 0x81, 0x53, 0x38, 0x7e, 0xc5, 0x9e, 0x71, 0xe5,
    0xc0, 0x19, 0x95, 0xdb, 0xef, 0xf6, 0x46, 0xc8, 0x95, 0x3d, 0x02, 0x21,
    0x00, 0xaa, 0xb1, 0xff, 0x8a, 0xa2, 0xb2, 0x2b, 0xef, 0x9a, 0x83, 0x3f,
    0xc5, 0xbc, 0xd4, 0x6a, 0x07, 0xe8, 0xc7, 0x0b, 0x2e, 0xd4, 0x0f, 0xf8,
    0x98, 0x68, 0xe1, 0x04, 0xa8, 0x92, 0xd0, 0x10, 0xaa,
};



void help() {
    std::cerr << "patchpolicy [/path/to/policy.XX] [info|patch]" << std::endl;
    exit(1);
}

void sign(uint8_t const key[], size_t keySize, std::string data, std::string* const signature, std::string* pubkey) {
    //create key
    CBS cbs;
    CBS_init(&cbs, key, keySize);
    EVP_PKEY* pkey = EVP_parse_private_key(&cbs);
    if (!pkey || CBS_len(&cbs) != 0 || EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        std::cerr << "sign: failed to create private key" << std::endl;
        exit(1);
    }

    std::cout << "sign: created private key" << std::endl;

    std::vector<uint8_t> pubkey_vec;
    uint8_t *der;
    size_t der_len;
    bssl::ScopedCBB cbb;
    if (!CBB_init(cbb.get(), 0) ||
        !EVP_marshal_public_key(cbb.get(), pkey) ||
        !CBB_finish(cbb.get(), &der, &der_len)) {
        std::cerr << "sign: failed to create public key" << std::endl;
        exit(1);
    }
    pubkey_vec.assign(der, der + der_len);
    OPENSSL_free(der);

    pubkey->assign(std::string(reinterpret_cast<const char*>(pubkey_vec.data()), pubkey_vec.size()));



    const EVP_MD* const digest = EVP_sha1();
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit(context, nullptr, digest, nullptr, pkey)) {
        std::cerr << "sign: failed to init signing context" << std::endl;
        exit(1);
    }
    std::cout << "sign: initted signing context" << std::endl;

    if (!EVP_DigestSignUpdate(context, data.c_str(), data.size())) {
        std::cerr << "sign: failed to update signing context" << std::endl;
        exit(1);
    }

    std::cout << "sign: updated signing context" << std::endl;

    std::vector<uint8_t> signature_bytes;
    // get max length of sig
    size_t lenSig = 0;
    if (!EVP_DigestSignFinal(context, nullptr, &lenSig)) {
        std::cerr << "sign: failed to finalize signature" << std::endl;
        exit(1);
    }
    signature_bytes.resize(lenSig);
    std::cout << "sign: finalizing signature pt1" << std::endl;

    if (!EVP_DigestSignFinal(context, signature_bytes.data(), &lenSig)) {
        std::cerr << "sign: failed to finalize signature" << std::endl;
        exit(1);
    }
    std::cout << "sign: finalized signature" << std::endl;
    signature_bytes.resize(lenSig);
    signature->assign(reinterpret_cast<const char*>(signature_bytes.data()),signature_bytes.size());
    std::cout << "sign: copied signature" << std::endl;
}

int main(int argc, char *argv[]) {
    enterprise_management::PolicyFetchResponse PFR;
    enterprise_management::PolicyData PD;
    enterprise_management::ChromeDeviceSettingsProto CDSP;
    string infile(argv[1]);

    fstream input(infile, ios::in | ios::binary);
    PFR.ParseFromIstream(&input);
    input.close();
    PD.ParseFromString(PFR.policy_data());
    CDSP.ParseFromString(PD.policy_value());

    if (argc != 3) {
        help();
    }

    if (!strcmp(argv[2], "info")) {
        std::cout << "PFR.has_policy_data_signature = " << PFR.has_policy_data_signature() << std::endl;
        std::cout << "GMEP.guest_mode_enabled = " << CDSP.guest_mode_enabled().guest_mode_enabled() << std::endl;
        std::cout << "CDSP.has_system_settings = " << CDSP.has_system_settings() << std::endl;
        if(CDSP.has_system_settings()) {
            enterprise_management::SystemSettingsProto SSP = CDSP.system_settings();
            std::cout << "SSP.block_devmode = " << SSP.block_devmode() << std::endl;
        }
    } else if (!strcmp(argv[2], "patch")) {
        /*
        * GuestModeEnabledProto instead of StartUp*
        * set_allocated_guest_mode_enabled
        *
        */
        enterprise_management::GuestModeEnabledProto GMEP = CDSP.guest_mode_enabled();
        GMEP.set_guest_mode_enabled(true);

        if(CDSP.has_system_settings()) {
            enterprise_management::SystemSettingsProto SSP = CDSP.system_settings();
            SSP.set_block_devmode(true);
            CDSP.set_allocated_system_settings(&SSP);
        }

        string PATCHED_CDSP;
        GMEP.SerializeToString(&PATCHED_CDSP);
        PD.set_policy_value(PATCHED_CDSP);

        string PATCHED_PD;
        PD.SerializeToString(&PATCHED_PD);
        std::cout << "signing" << std::endl;
        std::string pubkey = std::string();
        sign(kSigningKey, sizeof(kSigningKey), PFR.policy_data(), PFR.mutable_policy_data_signature(), &pubkey);
        PFR.set_new_public_key(pubkey);
        std::cout << "signed" << std::endl;
        PFR.set_policy_data(PATCHED_PD);

        ofstream output(infile, ios::out | ios::binary);
        PFR.SerializeToOstream(&output);
        output.close();

        ofstream keyout(infile+".key", ios::out | ios::binary);
        keyout << pubkey;
        keyout.close();
        std::cout << "wrote pubkey to file" << std::endl;
    } else {
        std::cerr << "invalid 2nd argument " << argv[2] << std::endl;
        help();
    }

    return 0;
}
