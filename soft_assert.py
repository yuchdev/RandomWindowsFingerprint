import re

class SoftAssert:

    message = ""

    @staticmethod
    def resolve(default_message):
        if SoftAssert.message != "":
            print(SoftAssert.message)
        else:
            print(default_message)
        SoftAssert.message = ""

    @staticmethod
    def are_euqal(actual, expected, message = "====="):
        if actual != expected:
            SoftAssert.message += "\n=====\n" + str(actual) + "\n" + str(expected) + "\nexpected to be equal\n" + str(message) + "\n====="


    @staticmethod
    def are_not_euqal(actual, expected, message = "====="):
        if actual == expected:
            SoftAssert.message += "\n=====\n" + str(actual) + "\n" + str(expected) + "\nexpected not to be equal\n" + str(message) + "\n====="

    @staticmethod
    def is_true(statement, message = "====="):
        if statement is not True:
            SoftAssert.message += "\n=====\n" + str(statement) + " expected to be true\n" + str(message) + "\n====="


    @staticmethod
    def is_regex(actual, regex, message = "====="):
        if not re.fullmatch(regex, actual):
            SoftAssert.message += "\n=====\n" + str(actual) + "\n" + str(regex) + "\nexpected to match the expression\n" + str(message) + "\n====="


    @staticmethod
    def is_in_list(actual, list_of_values, message = "====="):
        if not actual in list_of_values:
            SoftAssert.message += "\n=====\n" + str(actual) + "\n" + str(list_of_values) + "\nexpected to be in the list\n" + str(message) + "\n====="


    @staticmethod
    def is_binary_equal(actual, expected, message = "====="):
        if actual ^ expected:
            SoftAssert.message += "\n=====\n" + str(actual) + "\n" + str(expected) + "\nexpected to be equal\n" + str(message) + "\n====="
