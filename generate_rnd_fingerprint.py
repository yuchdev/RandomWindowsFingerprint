import os
import sys
import argparse
import logging
import platform
import log_helper
import win_fingerprint
import hardware_fingerprint
import random_utils
import registry_helper

from registry_helper import RegistryKeyType, Wow64RegistryEntry

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)


def is_x64os():
    """
    :return: True if system is 64-bit, False otherwise
    """
    return platform.machine().endswith('64')


def generate_network_fingerprint():
    """
    Generate network-related identifiers:
    Hostname (from pre-defined list)
    Username (from pre-defined list)
    MAC address (from pre-defined list)
    """
    random_host = random_utils.random_hostname()
    random_user = random_utils.random_username()
    random_mac = random_utils.random_mac_address()
    logger.info("Random hostname value is {0}".format(random_host))
    logger.info("Random username value is {0}".format(random_user))
    logger.info("Random MAC addresses value is {0}".format(random_mac))

    hive = "HKEY_LOCAL_MACHINE"
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="NV Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                value_name="RegisteredOwner",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_user,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)


def generate_windows_fingerprint():
    """
    Generate common Windows identifiers, responsible for fingerprinting:
    BuildGUID
    BuildLab
    BuildLabEx
    CurrentBuild
    CurrentBuildNumber
    CurrentVersion
    DigitalProductId
    DigitalProductId4
    EditionID
    InstallDate
    ProductId
    ProductName
    IE SvcKBNumber
    IE ProductId
    IE DigitalProductId
    IE DigitalProductId4
    IE Installed Date
    """
    system_fp = win_fingerprint.WinFingerprint()

    # Windows fingerprint
    hive = "HKEY_LOCAL_MACHINE"
    version_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildGUID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_guid(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLab",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLabEx",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab_ex(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuild",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuildNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentVersion",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_version(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="EditionID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_edition_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="InstallDate",
                                value_type=RegistryKeyType.REG_DWORD,
                                key_value=system_fp.random_install_date())
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)
    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_name(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    # IE fingerprint
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer",
                                value_name="svcKBNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_ie_service_update(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id())
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    ie_install_date = system_fp.random_ie_install_date()
    logger.info("IEDate={0}".format(ie_install_date))

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
                                value_name="IE Installed Date",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=ie_install_date,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    logger.info("Random build GUID {0}".format(system_fp.random_build_guid()))
    logger.info("Random BuildLab {0}".format(system_fp.random_build_lab()))
    logger.info("Random BuildLabEx {0}".format(system_fp.random_build_lab_ex()))
    logger.info("Random Current Build {0}".format(system_fp.random_current_build()))
    logger.info("Random Current Build number {0}".format(system_fp.random_current_build()))
    logger.info("Random Current Version {0}".format(system_fp.random_current_version()))
    logger.info("Random Edition ID {0}".format(system_fp.random_edition_id()))
    logger.info("Random Install Date {0}".format(system_fp.random_install_date()))
    logger.info("Random product ID {0}".format(system_fp.random_product_id()))
    logger.info("Random Product name {0}".format(system_fp.random_product_name()))
    logger.debug("Random digital product ID {0}".format(system_fp.random_digital_product_id()))
    logger.debug("Random digital product ID 4 {0}".format(system_fp.random_digital_product_id4()))
    logger.debug("Random IE service update {0}".format(system_fp.random_ie_service_update()))
    logger.debug("Random IE install data {0}".format(system_fp.random_ie_install_date()))


def generate_hardware_fingerprint():
    """
    Generate hardware-related identifiers:
    HwProfileGuid
    MachineGuid
    Volume ID
    SusClientId
    SusClientIDValidation
    """

    hardware_fp = hardware_fingerprint.HardwareFingerprint()

    hive = "HKEY_LOCAL_MACHINE"
    # Hardware profile GUID
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                                value_name="HwProfileGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_hw_profile_guid())

    # Machine GUID
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Cryptography",
                                value_name="MachineGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_machine_guid())

    # Windows Update GUID
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_win_update_guid())
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientIDValidation",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(hardware_fp.random_client_id_validation()))

    dir_name = os.path.join(os.path.dirname(__file__), "bin")
    volume_id = random_utils.random_volume_id()
    logger.info("VolumeID={0}".format(volume_id))
    volume_id_path = os.path.join(dir_name, "VolumeID{0}.exe C: {1}".format("64" if is_x64os() else "", volume_id))
    os.system(volume_id_path)

    logger.info("Random Hardware profile GUID {0}".format(hardware_fp.random_hw_profile_guid()))
    logger.info("Random Hardware CKCL GUID {0}".format(hardware_fp.random_performance_guid()))
    logger.info("Random Machine GUID {0}".format(hardware_fp.random_machine_guid()))
    logger.info("Random Windows Update GUID {0}".format(hardware_fp.random_win_update_guid()))
    logger.debug("Random Windows Update Validation ID {0}".format(hardware_fp.random_win_update_guid()))


def main():
    """
    Generate and change/spoof Windows identification to protect user from local installed software
    :return: Exec return code
    """

    parser = argparse.ArgumentParser(description='Command-line interface')

    parser.add_argument('--network',
                        help='Rewrite existing backup file if exist',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--system',
                        help='Rewrite existing backup file if exist',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--hardware',
                        help='Rewrite existing backup file if exist',
                        action='store_true',
                        required=False,
                        default=False)

    args = parser.parse_args()

    # Selected nothing means select all
    if args.network is False and args.system is False and args.hardware is False:
        args.network = True
        args.system = True
        args.hardware = True

    if args.network:
        generate_network_fingerprint()
    if args.system:
        generate_windows_fingerprint()
    if args.hardware:
        generate_hardware_fingerprint()

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
