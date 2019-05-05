import os
import logging
import log_helper

import generate_fingerprint as gen

import validatable_record
from test_type import TestType
from validation_type import ValidationType

logger = log_helper.setup_logger(name="antidetect", level=logging.INFO, log_to_file=False)

def get_registry_comfig():
    return [
        validatable_record.ValidatableRecord(
            type = TestType.network_fingerprint,
            path = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name = "NV Hostname",
            validation_format = ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type = TestType.network_fingerprint,
            path = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name = "Hostname",
            validation_format = ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type = TestType.network_fingerprint,
            path = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
            name = "ComputerName",
            validation_format = ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type = TestType.network_fingerprint,
            path = "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName ",
            name = "ComputerName",
            validation_format = ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type = TestType.network_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name =  "RegisteredOwner",
            validation_format = ValidationType.host_name),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "BuildGUID",
            validation_format = ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "BuildLabEx",
            validation_format = ValidationType.build_lab_ex),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "CurrentBuild",
            validation_format = ValidationType.current_build),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "CurrentBuildNumber",
            validation_format = ValidationType.current_build),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "CurrentVersion",
            validation_format = ValidationType.current_version),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "EditionID",
            validation_format = ValidationType.edition_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "ProductId",
            validation_format = ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "ProductName",
            validation_format = ValidationType.product_name),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "BuildLab",
            validation_format = ValidationType.build_lab),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "DigitalProductId4",
            validation_format = ValidationType.digital_product_id4),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "DigitalProductId",
            validation_format = ValidationType.digital_product_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "ProductId",
            validation_format = ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            name = "InstallDate",
            validation_format = ValidationType.unix_time),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Internet Explorer",
            name = "svcKBNumber",
            validation_format = ValidationType.svc_kb_number),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name = "ProductId",
            validation_format = ValidationType.product_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name = "DigitalProductId",
            validation_format = ValidationType.digital_product_id),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Internet Explorer\\Registration ",
            name = "DigitalProductId4",
            validation_format = ValidationType.digital_product_id4),
        validatable_record.ValidatableRecord(
            type = TestType.windows_fingerprint,
            path = "SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
            name = "IE Installed Date",
            validation_format = ValidationType.ie_installed_date),
        validatable_record.ValidatableRecord(
            type = TestType.hardware_fingerprint,
            path = "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
            name = "HwProfileGuid",
            validation_format = ValidationType.curl_uuid),
        validatable_record.ValidatableRecord(
            type = TestType.hardware_fingerprint,
            path = "SOFTWARE\\Microsoft\\Cryptography",
            name = "MachineGuid",
            validation_format = ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type = TestType.hardware_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            name = "SusClientId",
            validation_format = ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type = TestType.hardware_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            name = "SusClientIDValidation",
            validation_format = ValidationType.none),
        validatable_record.ValidatableRecord(
            type = TestType.telemetry_fingerprint,
            path = "SOFTWARE\\Microsoft\\SQMClient ",
            name = "MachineId",
            validation_format = ValidationType.uuid),
        validatable_record.ValidatableRecord(
            type = TestType.telemetry_fingerprint,
            path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests",
            name = "ETagQueryParameters",
            validation_format = ValidationType.none)
    ]


def generate_fingerprint(test_type):
    if test_type == TestType.telemetry_fingerprint:
        gen.generate_telemetry_fingerprint()
    if test_type == TestType.network_fingerprint:
        gen.generate_network_fingerprint()
    if test_type == TestType.windows_fingerprint:
        gen.generate_windows_fingerprint()
    if test_type == TestType.hardware_fingerprint:
        os.system("win_fingerprint.exe --hardware")
    if test_type == TestType.font_fingerprint:
        gen.generate_font_fingerprint()


def generic_test(test_type):
    registry_config = get_registry_comfig()
    to_change = []
    to_preserve = []
    for record in registry_config:
        if record.initial_value is None: continue
        if record.type == test_type: 
            record.corrupt()
            to_change.append(record)
        else: to_preserve.append(record)

    generate_fingerprint(test_type)

    for record in to_change:
        record.should_change()
        record.validate_format()

    for record in to_preserve:
        record.should_not_change()

    logger.info("Test was successful: " + str(test_type))


# generic_test(TestType.telemetry_fingerprint)
# generic_test(TestType.network_fingerprint)
# generic_test(TestType.windows_fingerprint)
generic_test(TestType.hardware_fingerprint)
