#include <algorithm>
#include <cstring>
#include <iterator>
#include <openssl/evp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <filesystem>

#include "device_management_backend.pb.h"
#include "chrome_device_policy.pb.h"
#include "boringssl/install/include/openssl/evp.h"
#include "boringssl/install/include/openssl/bn.h"
#include "boringssl/install/include/openssl/bytestring.h"
#include "boringssl/install/include/openssl/base.h"
#include "boringssl/install/include/openssl/mem.h"
#include "boringssl/install/include/openssl/rsa.h"

using namespace std;

/*
 * holy shit, we actually have device policy editing, holy fucking bingle what?! :3
 * rip ultrablue 07
 *
 * to add a policy value:
 *  - find the policy protobuf class
 *  - create a new const variable below the other ones, label it properly, and set the value
 *  - in patch() copy one of the existing policy editors and modify it
 *  - in help() add a new line that prints the const variable
 *  - if info() does not print out the value of the policy already, add it
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

const bool GMEV = 1;              // GuestModeEnabledProto
const bool SUNOSV = 1;            // ShowUserNamesOnSigninProto
const bool PVAV = 1;              // PluginVmAllowedProto
const bool VMAV = 1;              // VirtualMachinesAllowedProto
const bool DUCAV = 1;             // DeviceUnaffiliatedCrostiniAllowedProto
const std::string RCP_MRCV = "";  // ReleaseChannelProto.mutable_release_lts_tag
const bool SSPV = 0;              // SystemSettingsProto.block_devmode
const std::string DWIP_MDWIV = "{ \"hash\": \"f0f4170422c4c3c0c6a4cd8b7b71479b1a9b8f258a321110ee456e228390e8aa\", \"url\": \"https://cdn.r58playz.dev/sh1mmerbg.jpeg\" }"; // DeviceWallpaperImageProto.mutable_device_wallpaper_image


bool file_exists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}

void help(int exitcode) {
    std::cerr << "lilac is a device policy editor for chromeos." << std::endl;
    std::cerr << "lilac [/var/lib/devicesettings/policy.XX] [info|patch|help|--help|-h]" << std::endl;
    std::cerr << "arguments:" << std::endl;
    std::cerr << "    info:" << std::endl;
    std::cerr << "        show some info about the policy file including what policy values are" << std::endl;
    std::cerr << "    patch:" << std::endl;
    std::cerr << "        patch the given policy file" << std::endl;
    std::cerr << "    help|--help|-h:" << std::endl;
    std::cerr << "        show this help" << std::endl;
    std::cerr << "usage:" << std::endl;
    std::cerr << "    run lilac on a policy file with patch" << std::endl;
    std::cerr << "    lilac will modify the policy file and create a new file called owner.key" << std::endl;
    std::cerr << "    copy the files to /var/lib/devicesettings and turn wifi off so chrome doesn't sync policies" << std::endl;
    std::cerr << "this version of lilac sets:" << std::endl;
    std::cerr << "    guest_mode_enabled = "                   << GMEV << std::endl;
    std::cerr << "    show_user_names = "                      << SUNOSV << std::endl;
    std::cerr << "    plugin_vm_allowed = "                    << PVAV << std::endl;
    std::cerr << "    virtual_machines_allowed = "             << VMAV << std::endl;
    std::cerr << "    device_unaffiliated_crostini_allowed = " << DUCAV << std::endl;
    std::cerr << "    release_lts_tag = "                      << RCP_MRCV << std::endl;
    std::cerr << "    device_wallpaper_image = "               << DWIP_MDWIV << std::endl;
    std::cerr << "    block_devmode = "                        << SSPV << std::endl;
    exit(exitcode);
}

void sign(uint8_t const key[], size_t keySize, std::string data, std::string* const signature, std::string* pubkey) {
    CBS cbs;
    CBS_init(&cbs, key, keySize);
    EVP_PKEY* pkey = EVP_parse_private_key(&cbs);
    if (!pkey || CBS_len(&cbs) != 0 || EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
        std::cerr << "sign: failed to create private key" << std::endl;
        exit(1);
    }

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

    if (!EVP_DigestSignUpdate(context, data.c_str(), data.size())) {
        std::cerr << "sign: failed to update signing context" << std::endl;
        exit(1);
    }

    std::vector<uint8_t> signature_bytes;
    // get max length of sig
    size_t lenSig = 0;
    if (!EVP_DigestSignFinal(context, nullptr, &lenSig)) {
        std::cerr << "sign: failed to finalize signature" << std::endl;
        exit(1);
    }
    signature_bytes.resize(lenSig);

    if (!EVP_DigestSignFinal(context, signature_bytes.data(), &lenSig)) {
        std::cerr << "sign: failed to finalize signature" << std::endl;
        exit(1);
    }
    signature_bytes.resize(lenSig);
    signature->assign(reinterpret_cast<const char*>(signature_bytes.data()),signature_bytes.size());
    OPENSSL_free(context);
    OPENSSL_free(pkey);
}

void info(enterprise_management::ChromeDeviceSettingsProto* CDSP) {
    std::cout << "DevicePolicyRefreshRate = " << CDSP->device_policy_refresh_rate().device_policy_refresh_rate() << std::endl;
    std::cout << "UserWhitelistProto = ";
    if(CDSP->user_whitelist().user_whitelist_size() == 0) {
        std::cout << std::endl;
    } else {
        for(int i = 0; i < CDSP->user_whitelist().user_whitelist_size(); i++) {
            std::cout << "                     " << CDSP->user_whitelist().user_whitelist().Get(i) << std::endl;
        }
    }
    std::cout << "DeviceGuestModeEnabled = " << CDSP->guest_mode_enabled().guest_mode_enabled() << std::endl;
    std::cout << "CameraEnabledProto = " << CDSP->camera_enabled().camera_enabled() << std::endl;
    std::cout << "DeviceShowUserNamesOnSignin = " << CDSP->show_user_names().show_user_names() << std::endl;
    std::cout << "DeviceDataRoamingEnabled = " << CDSP->data_roaming_enabled().data_roaming_enabled() << std::endl;
    std::cout << "DeviceAllowNewUsers = " << CDSP->allow_new_users().allow_new_users() << std::endl;
    std::cout << "DeviceMetricsReportingEnabled = " << CDSP->metrics_enabled().metrics_enabled() << std::endl;\
    std::cout << "ChromeOsReleaseChannel = " << CDSP->release_channel().release_channel() << std::endl;
    std::cout << "DeviceOpenNetworkConfiguration = " << CDSP->open_network_configuration().open_network_configuration() << std::endl;
    std::cout << "DeviceReportingProto is currently not implemented for parsing" << std::endl;
    std::cout << "DeviceEphemeralUsersEnabled = " << CDSP->ephemeral_users_enabled().ephemeral_users_enabled() << std::endl;
    std::cout << "DeviceAutoUpdateDisabled = " << CDSP->auto_update_settings().update_disabled() << std::endl;
    std::cout << "DeviceAutoUpdateP2PEnabled = " << CDSP->auto_update_settings().p2p_enabled() << std::endl;
    std::cout << "DeviceAutoUpdateTimeRestrictions = " << CDSP->auto_update_settings().disallowed_time_intervals() << std::endl;
    std::cout << "SystemTimezone = " << CDSP->system_timezone().timezone() << std::endl;
    std::cout << "SystemTimezoneAutomaticDetection = " << CDSP->system_timezone().timezone_detection_type() << std::endl;
    std::cout << "DeviceLocalAccounts is currently not implemented for parsing" << std::endl;
    std::cout << "DeviceAllowRedeemChromeOsRegistrationOffers = " << CDSP->allow_redeem_offers().allow_redeem_offers() << std::endl;
    std::cout << "FeatureFlagsProto is currently not implemented for parsing" << std::endl;
    std::cout << "UptimeLimit = " << CDSP->uptime_limit().uptime_limit() << std::endl;
    std::cout << "DeviceChromeVariations = " << CDSP->device_chrome_variations_type().value() << std::endl;
    std::cout << "AttestationSettingsProto is currently not implemented for parsing" << std::endl;
    std::cout << "AccessibilitySettingsProto is currently not implemented for parsing" << std::endl;
    std::cout << "LoginScreenPowerManagement = " << CDSP->login_screen_power_management().login_screen_power_management() << std::endl;
    std::cout << "SystemUse24HourClock = " << CDSP->use_24hour_clock().use_24hour_clock() << std::endl;
    std::cout << "AutoCleanupSettigsProto (yes they misspelled it lmfao) is currently not implemented for parsing" << std::endl;
    std::cout << "SAMLSettingsProto is currently not implemented for parsing" << std::endl;
    std::cout << "DeviceRebootOnShutdown = " << CDSP->reboot_on_shutdown().reboot_on_shutdown() << std::endl;
    std::cout << "DeviceHeartbeatSettingsProto is currently not implemented for parsing" << std::endl;

    std::cout << "PluginVmAllowed = " << CDSP->plugin_vm_allowed().plugin_vm_allowed() << std::endl;
    std::cout << "VirtualMachinesAllowed = " << CDSP->virtual_machines_allowed().virtual_machines_allowed() << std::endl;
    std::cout << "DeviceUnaffiliatedCrostiniAllowed = " << CDSP->device_unaffiliated_crostini_allowed().device_unaffiliated_crostini_allowed() << std::endl;
    std::cout << "release_lts_tag = " << CDSP->release_channel().release_lts_tag() << std::endl;
    std::cout << "DeviceWallpaperImage = " << CDSP->device_wallpaper_image().device_wallpaper_image() << std::endl;
    if(CDSP->has_system_settings()) {
        enterprise_management::SystemSettingsProto SSP = CDSP->system_settings();
        std::cout << "DeviceBlockDevmode = " << SSP.block_devmode() << std::endl;
    }
}

void patch(enterprise_management::ChromeDeviceSettingsProto* CDSP) {
    enterprise_management::GuestModeEnabledProto* GMEP = CDSP->mutable_guest_mode_enabled();
    GMEP->set_guest_mode_enabled(GMEV);

    enterprise_management::ShowUserNamesOnSigninProto* SUNOSP = CDSP->mutable_show_user_names();
    SUNOSP->set_show_user_names(SUNOSV);

    enterprise_management::PluginVmAllowedProto* PVAP = CDSP->mutable_plugin_vm_allowed();
    PVAP->set_plugin_vm_allowed(PVAV);

    enterprise_management::VirtualMachinesAllowedProto* VMAP = CDSP->mutable_virtual_machines_allowed();
    VMAP->set_virtual_machines_allowed(VMAV);

    enterprise_management::DeviceUnaffiliatedCrostiniAllowedProto* DUCAP = CDSP->mutable_device_unaffiliated_crostini_allowed();
    DUCAP->set_device_unaffiliated_crostini_allowed(DUCAV);

    enterprise_management::ReleaseChannelProto* RCP = CDSP->mutable_release_channel();
    std::string* RCP_MRC = RCP->mutable_release_lts_tag();
    RCP_MRC->assign(RCP_MRCV);

    enterprise_management::DeviceWallpaperImageProto* DWIP = CDSP->mutable_device_wallpaper_image();
    std::string* DWIP_MDWI = DWIP->mutable_device_wallpaper_image();
    DWIP_MDWI->assign(DWIP_MDWIV);

    if(CDSP->has_system_settings()) {
        enterprise_management::SystemSettingsProto* SSP = CDSP->mutable_system_settings();
        SSP->set_block_devmode(SSPV);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "lilac: not enough arguments" << std::endl;
        help(1);
    } else if(!strcmp(argv[2], "help")) {
        help(0);
    } else if(!strcmp(argv[2], "--help")) {
        help(0);
    } else if(!strcmp(argv[2], "-h")) {
        help(0);
    }

    string infile(argv[1]);

    if(!file_exists(infile)) {
        std::cerr << "lilac: input policy file does not exist" << std::endl;
        exit(1);
    }
    std::filesystem::path infilepath = infile; // bro i imported filesystem why is clangd complainingggg
    std::string parent = infilepath.parent_path().string();

    fstream input(infile, ios::in | ios::binary);
    enterprise_management::PolicyFetchResponse PFR;
    enterprise_management::PolicyData PD;
    enterprise_management::ChromeDeviceSettingsProto CDSP;
    PFR.ParseFromIstream(&input);
    input.close();
    PD.ParseFromString(PFR.policy_data());
    CDSP.ParseFromString(PD.policy_value());

    if (!strcmp(argv[2], "info")) {
        std::cout << "PFR.has_policy_data_signature = " << PFR.has_policy_data_signature() << std::endl;
        info(&CDSP);
    } else if (!strcmp(argv[2], "patch")) {
        patch(&CDSP);

        string PATCHED_CDSP;
        CDSP.SerializeToString(&PATCHED_CDSP);
        PD.set_policy_value(PATCHED_CDSP);

        string PATCHED_PD;
        PD.SerializeToString(&PATCHED_PD);
        std::string pubkey = std::string();
        sign(kSigningKey, sizeof(kSigningKey), PFR.policy_data(), PFR.mutable_policy_data_signature(), &pubkey);
        PFR.set_new_public_key(pubkey);
        PFR.set_policy_data(PATCHED_PD);

        ofstream output(infile, ios::out | ios::binary);
        PFR.SerializeToOstream(&output);
        output.close();

        ofstream keyout(parent + "owner.key", ios::out | ios::binary);
        keyout << pubkey;
        keyout.close();
    } else {
        std::cerr << "invalid 2nd argument " << argv[2] << std::endl;
        help(1);
    }

    return 0;
}
