import unittest
import system_utils


__doc__ = """Module for testing general system-related functions"""


class TestSystemUtils(unittest.TestCase):

    def test_replace_string(self):
        print("Is Platform x64: %s" % system_utils.is_x64os())
        print("Platform version: %s" % system_utils.platform_version())
        print("Platform system: %s" % system_utils.platform_system())
        self.assertTrue(system_utils.is_x64os())
        self.assertTrue(system_utils.platform_version())
        self.assertTrue(system_utils.platform_system())


if __name__ == "__main__":
    unittest.main()
