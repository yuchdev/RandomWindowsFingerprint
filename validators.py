import re
import time


def validate_uuid(to_validate):
    return bool(re.fullmatch('[0-9,a-f,A-F]{8}-[0-9,a-f,A-F]{4}-[0-9,a-f,A-F]{4}-[0-9,a-f,A-F]{4}-[0-9,a-f,A-F]{12}', to_validate))


def validate_curl_uuid(uuid_string):
    return ((uuid_string[0] == "{") and (uuid_string[-1] == "}") and validate_uuid(uuid_string[1:-1]))


def validate_product_id(to_validate):
    return bool(re.fullmatch('[0-9]{5}-[0-9,O][0-9,E][0-9,M]-[0-9]{7}-[0-9]{5}', to_validate))


def validate_unix_time(to_validate):
    return to_validate < int(time.time())


def validate_ie_installed_date(to_validate):
    return validate_unix_time(int.from_bytes(to_validate[0:3], byteorder='big')) and len(to_validate) == 8


def validate_build_lab(to_validate):
    ListBuildLab = ['7601.win7sp1_ldr.170913-0600', '9600.winblue_r4.141028-1500', '16299.rs3_release.170928-1534']
    return to_validate in ListBuildLab


def validate_build_lab_ex(to_validate):
    ListBuildLabEx = ['7601.23915.amd64fre.win7sp1_ldr.170913-0600', '9600.17415.amd64fre.winblue_r4.141028-1500', '16299.15.amd64fre.rs3_release.170928-1534']
    return to_validate in ListBuildLabEx


def validate_current_build(to_validate):
    ListCurrentBuild = ['7601', '9600', '16299']
    return to_validate in ListCurrentBuild


def validate_current_version(to_validate):
    ListCurrentVersion = ['6.1', '7.1', '9.0']
    return to_validate in ListCurrentVersion


def validate_edition_id(to_validate):
    ListEditionId = ["Starter", "HomeBasic", "HomePremium", "Professional", "ProfessionalN", "ProfessionalKN", "Enterprise", "Ultimate", "Core", "Pro", "ProN", "Enterprise", "EnterpriseN", "OEM", "withBing", "Home", "ProEducation", "EnterpriseLTSB", "Education", "IoTCore", "IoTEnterprise", "S"]
    return to_validate in ListEditionId


def validate_product_name(to_validate):
    ListProductName = ["Windows 7", "Windows 8.1", "Windows 10"]
    return to_validate in ListProductName


def validate_svc_kb_number(to_validate):
    ListKbNumber = ["KB2841134", "KB4088835", "KB4032782", "KB4016446", "KB3210694", "KB3200006", "KB3199375", "KB3192665", "KB4096040", "KB4089187", "KB4074736", "KB4056568", "KB4052978", "KB4047206", "KB4040685", "KB4036586", "KB4034733", "KB4025252", "KB4021558", "KB4018271", "KB4014661", "KB4012204", "KB3185319", "KB3175443", "KB3170106", "KB3160005", "KB3154070", "KB3148198"]
    return to_validate in ListKbNumber


def validate_host_name(to_validate):
    return bool(re.fullmatch("^[a-zA-Z][a-zA-Z0-9]*$", to_validate))


def validate_digital_product_id(to_validate):
    return True


def validate_digital_product_id4(to_validate):
    return True


def validate_sus_client_id_validation(to_validate):
    return True

