import os
import sys
import argparse
import logging
import enum
import log_helper
import validatable_record
import generate_fingerprint as gen

from soft_assert import SoftAssert
from test_type import TestType
from validation_type import ValidationType


logger = log_helper.setup_logger(name="fingerprint_test", level=logging.DEBUG, log_to_file=False)


class ApplicationType(enum.IntEnum):
    APP_PROTOTYPE = 0
    APP_PRODUCTION = 1


TEST_TYPE_MAP = {
    "telemetry": TestType.telemetry_fingerprint,
    "network": TestType.network_fingerprint,
    "system": TestType.windows_fingerprint,
    "hardware": TestType.hardware_fingerprint,
    "font": TestType.font_fingerprint
}


def get_registry_config():
    """
    :return: List of all registry values of ValidatableRecord type,
    which instances are edited during fingerprint spoofing
    """
    return [
        validatable_record.ValidatableRecord(
            type=TestType.network_fingerprint,
            path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name="NV Hostname",
            validation_format=ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type=TestType.network_fingerprint,
            path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name="Hostname",
            validation_format=ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type=TestType.network_fingerprint,
            path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name="ComputerName",
            validation_format=ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type=TestType.network_fingerprint,
            path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName ",
            name="ComputerName",
            validation_format=ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type=TestType.network_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="RegisteredOwner",
            validation_format=ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="BuildGUID",
            validation_format=ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="BuildLabEx",
            validation_format=ValidationType.build_lab_ex),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="CurrentBuild",
            validation_format=ValidationType.current_build),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="CurrentBuildNumber",
            validation_format=ValidationType.current_build),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="CurrentVersion",
            validation_format=ValidationType.current_version),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="EditionID",
            validation_format=ValidationType.edition_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="ProductId",
            validation_format=ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="ProductName",
            validation_format=ValidationType.product_name),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="BuildLab",
            validation_format=ValidationType.build_lab),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="DigitalProductId4",
            validation_format=ValidationType.digital_product_id4),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="DigitalProductId",
            validation_format=ValidationType.digital_product_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="ProductId",
            validation_format=ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name="InstallDate",
            validation_format=ValidationType.unix_time),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Internet Explorer",
            name="svcKBNumber",
            validation_format=ValidationType.svc_kb_number),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name="ProductId",
            validation_format=ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name="DigitalProductId",
            validation_format=ValidationType.digital_product_id),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name="DigitalProductId4",
            validation_format=ValidationType.digital_product_id4),
        validatable_record.ValidatableRecord(
            type=TestType.windows_fingerprint,
            path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
            name="IE Installed Date",
            validation_format=ValidationType.ie_installed_date),
        validatable_record.ValidatableRecord(
            type=TestType.hardware_fingerprint,
            path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
            name="HwProfileGuid",
            validation_format=ValidationType.curl_uuid),
        validatable_record.ValidatableRecord(
            type=TestType.hardware_fingerprint,
            path="SOFTWARE\\Microsoft\\Cryptography",
            name="MachineGuid",
            validation_format=ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type=TestType.hardware_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            name="SusClientId",
            validation_format=ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type=TestType.hardware_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            name="SusClientIDValidation",
            validation_format=ValidationType.none),
        validatable_record.ValidatableRecord(
            type=TestType.telemetry_fingerprint,
            path="SOFTWARE\\Microsoft\\SQMClient ",
            name="MachineId",
            validation_format=ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type=TestType.telemetry_fingerprint,
            path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests",
            name="ETagQueryParameters",
            validation_format=ValidationType.none)
    ]


def generate_prototype_fingerprint(test_type):
    """
    Run test suite for prototype application
    :param test_type: TestType enum value
    """
    if test_type == TestType.telemetry_fingerprint:
        gen.generate_telemetry_fingerprint()
    if test_type == TestType.network_fingerprint:
        gen.generate_network_fingerprint()
    if test_type == TestType.windows_fingerprint:
        gen.generate_windows_fingerprint()
    if test_type == TestType.hardware_fingerprint:
        gen.generate_hardware_fingerprint()
    if test_type == TestType.font_fingerprint:
        gen.generate_font_fingerprint()


def generate_production_fingerprint(test_type):
    """
    Run test suite for production application
    :param test_type: TestType enum value
    """
    if test_type == TestType.telemetry_fingerprint:
        os.system("win_fingerprint.exe --telemetry")
    if test_type == TestType.network_fingerprint:
        os.system("win_fingerprint.exe --network")
    if test_type == TestType.windows_fingerprint:
        os.system("win_fingerprint.exe --system")
    if test_type == TestType.hardware_fingerprint:
        os.system("win_fingerprint.exe --hardware")
    if test_type == TestType.font_fingerprint:
        os.system("win_fingerprint.exe --font")


def generic_test(test_type, application_type):

    assert type(application_type) is ApplicationType, "application_type should be Enum.ApplicationType"

    logger.info("Run generic test test_type={}, application_type={}".format(test_type, application_type))

    registry_config = get_registry_config()
    to_change = []
    to_preserve = []
    to_not_exist = []
    for record in registry_config:
        if record.initial_value is None: 
            to_not_exist.append(record)
            continue
        if record.type == test_type:
            record.corrupt()
            to_change.append(record)
        else:
            to_preserve.append(record)

    if application_type == ApplicationType.APP_PROTOTYPE:
        generate_prototype_fingerprint(test_type)
    elif application_type == ApplicationType.APP_PRODUCTION:
        generate_production_fingerprint(test_type)
    else:
        logger.warning("generic_test(test_type, application_type): application_type is out of range")

    for record in to_change:
        record.should_change()
        record.validate_format()

    for record in to_preserve:
        record.should_not_change()

    for record in to_not_exist:
        record.should_not_exist()

    SoftAssert.resolve("Test was successful: " + str(test_type))


def main():
    """
    Run test suite for either prototype or production application
    :return: Exec return code
    """

    parser = argparse.ArgumentParser(description='Command-line parameters')

    parser.add_argument('--prototype',
                        help='Run test for prototype application',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--production',
                        help='Run test for production application',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--test-type',
                        help='List of test types to run',
                        nargs='+',
                        type=str,
                        default=["telemetry", "network", "system", "hardware"],
                        required=False)

    application_type = ApplicationType.APP_PROTOTYPE
    args = parser.parse_args()

    if args.prototype and args.production:
        logger.warning("Choose either --prototype or --production")
        return 0

    if args.prototype:
        logger.info("Use prototype application")
        application_type = ApplicationType.APP_PROTOTYPE
    elif args.production:
        logger.info("Use production application")
        application_type = ApplicationType.APP_PRODUCTION
    else:
        logger.warning("Choose either --prototype or --production, --prototype is default")

    for test_type in args.test_type:
        generic_test(TEST_TYPE_MAP[test_type], application_type)

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
