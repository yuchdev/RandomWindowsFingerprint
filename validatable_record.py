import winreg
import registry_helper
import validation_type
import validators
from soft_assert import SoftAssert


class ValidatableRecord:
    def __init__(self, path, name, test_type=None, validation_format=validation_type.ValidationType.none):
        self.path = path
        self.name = name
        self.type = test_type
        self.validation_format = validation_format
        self.initial_value = self.read()

    def read(self):
        try:
            to_return, _ = registry_helper.read_value(
                key_hive="HKEY_LOCAL_MACHINE",
                key_path=self.path,
                value_name=self.name)
            return to_return
        except:
            return None

    def save_initial_value(self):
        self.initial_value = self.read()

    def corrupt(self):
        read_result = self.read()
        if read_result is None:
            return None

        _, value_type = registry_helper.read_value(key_hive="HKEY_LOCAL_MACHINE", key_path=self.path,
                                                   value_name=self.name)

        value = 42
        if value_type == winreg.REG_SZ: value = "42"
        if value_type == 3: value = b'\x42'

        registry_helper.write_value(
            key_hive="HKEY_LOCAL_MACHINE",
            key_path=self.path,
            value_name=self.name,
            value_type=value_type,
            key_value=value)

        self.initial_value = value
        return value

    def should_change(self):
        SoftAssert.are_not_euqal(self.read(), self.initial_value, self.path + " / " + self.name)

    def should_not_change(self):
        SoftAssert.are_euqal(self.read(), self.initial_value, self.path + " / " + self.name)

    def should_not_exist(self):
        should_be_none = self.read()
        SoftAssert.is_true(should_be_none is None, should_be_none)

    def validate_format(self):
        if self.validation_format == validation_type.ValidationType.product_id:
            validators.validate_product_id(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.unix_time:
            validators.validate_unix_time(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.digital_product_id:
            validators.validate_digital_product_id(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.digital_product_id4:
            validators.validate_digital_product_id4(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.build_lab:
            validators.validate_build_lab(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.build_lab_ex:
            validators.validate_build_lab_ex(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.current_build:
            validators.validate_current_build(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.uuid:
            validators.validate_uuid(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.curl_uuid:
            validators.validate_curl_uuid(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.current_version:
            validators.validate_current_version(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.edition_id:
            validators.validate_edition_id(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.product_name:
            validators.validate_product_name(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.svc_kb_number:
            validators.validate_svc_kb_number(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.host_name:
            validators.validate_host_name(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.sus_client_id_validation:
            validators.validate_sus_client_id_validation(self.read(), self.path + "/" + self.name)

        if self.validation_format == validation_type.ValidationType.ie_installed_date:
            validators.validate_ie_installed_date(self.read(), self.path + "/" + self.name)
