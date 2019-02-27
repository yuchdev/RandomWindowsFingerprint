import sys
import logging
import log_helper
import random
import registry_helper


logger = log_helper.setup_logger(name="font_fp", level=logging.INFO, log_to_file=False)


__doc__ = "The script deletes N random fonts from the system"


def delete_random_font(fonts_delete):
    """
    Delete several random fonts from the system
    :param fonts_delete: Fonts to delete
    """
    hive = "HKEY_LOCAL_MACHINE"

    fonts_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts"
    hidden_fonts_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts\\Hidden"

    if not registry_helper.is_key_exist(hive, hidden_fonts_key):
        registry_helper.create_key(hive, hidden_fonts_key)

    fonts64 = registry_helper.enumerate_key_values(hive, fonts_key)

    for _ in range(0, fonts_delete):
        delete_font = random.choice(fonts64)
        logger.info("Delete font {0}".format(delete_font))
        logger.info("DEBUG: registry_helper.create_value({0})".format(delete_font))
        rc = registry_helper.create_value(hive, hidden_fonts_key, delete_font[0], delete_font[2], delete_font[1])
        if rc:
            logger.info("DEBUG: registry_helper.delete_value({0})".format(delete_font))
            registry_helper.delete_value(hive, hidden_fonts_key, delete_font[0])


def main():
    """
    :return: Exec return code
    """
    if len(sys.argv) > 2:
        print("Usage: delete_random_font.py <N>")
        return 0

    if len(sys.argv) == 2:
        fonts_to_erase = int(sys.argv[1])
    else:
        fonts_to_erase = random.randint(3, 12)

    delete_random_font(fonts_to_erase)
    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
