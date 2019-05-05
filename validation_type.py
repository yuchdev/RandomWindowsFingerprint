import enum

class ValidationType(enum.IntEnum):
    none = 0
    product_id=1
    unix_time=2
    digital_product_id=3
    digital_product_id4=4
    build_lab=5
    build_lab_ex=6
    current_build=7
    uuid=8
    curl_uuid=9
    edition_id=10
    product_name=11
    svc_kb_number =12
    host_name = 13
    sus_client_id_validation = 14
    ie_installed_date=15
    current_version=16
    