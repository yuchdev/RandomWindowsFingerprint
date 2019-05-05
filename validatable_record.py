import winreg
import registry_helper
import validation_type
import validators

class ValidatableRecord:
    def __init__(self, path, name, type = None, validation_format = validation_type.ValidationType.none):
        self.path = path
        self.name = name
        self.type = type
        self.validation_format = validation_format
        self.initial_value = self.read()

    def read(self):
        try:
            to_return, _ = registry_helper.read_value(
                key_hive="HKEY_LOCAL_MACHINE",
                key_path=self.path,
                value_name=self.name)
            return to_return
        except: return None

    
    def save_initial_value(self):
        self.initial_value = self.read()


    def corrupt(self):
        read_result = self.read()
        if read_result is None:
            return None

        _, value_type = registry_helper.read_value(key_hive="HKEY_LOCAL_MACHINE", key_path=self.path, value_name=self.name)

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
        assert self.initial_value != self.read(), \
            "Expected " + self.path + " / " + self.name + \
            " to change from " + self.initial_value


    def should_not_change(self):
        assert self.initial_value == self.read(), \
            "Expected " + self.path + " / " + self.name + \
            "\nto be: " + self.initial_value + \
            "\nnot:   " + self.read()


    def validate_format(self):
        if self.validation_format == validation_type.ValidationType.product_id: 
            assert validators.validate_product_id(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.unix_time: 
            assert validators.validate_unix_time(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.digital_product_id: 
            assert validators.validate_digital_product_id(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.digital_product_id4: 
            assert validators.validate_digital_product_id4(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.build_lab: 
            assert validators.validate_build_lab(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.build_lab_ex: 
            assert validators.validate_build_lab_ex(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.current_build: 
            assert validators.validate_current_build(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.uuid: 
            assert validators.validate_uuid(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.curl_uuid: 
            assert validators.validate_curl_uuid(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.current_version: 
            assert validators.validate_current_version(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.edition_id: 
            assert validators.validate_edition_id(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.product_name: 
            assert validators.validate_product_name(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.svc_kb_number: 
            assert validators.validate_svc_kb_number(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.host_name: 
            assert validators.validate_host_name(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.sus_client_id_validation: 
            assert validators.validate_sus_client_id_validation(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
        
        if self.validation_format == validation_type.ValidationType.ie_installed_date: 
            assert validators.validate_ie_installed_date(self.read()), \
                "Invalid format " + str(self.validation_format) + " for " + self.name + ": " + self.read()
