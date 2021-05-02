import platform


__doc__ = """Module contains general system-related functions"""


def is_x64os():
    """
    :return: True if system is 64-bit, False otherwise
    """
    return platform.machine().endswith('64')


def platform_version():
    """
    :return:
    """
    return platform.platform()

def platform_system():
    """
    :return: 
    """
    return platform.system()
