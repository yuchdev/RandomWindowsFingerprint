import uuid

__doc__ = """All the telemetry is getting around the DeviceID registry value
It can be found in the following kays:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests

For example:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests\telemetry.ASM-WindowsDefault
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests\telemetry.ASM-WindowsSQ
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests\telemetry.P-ARIA-d5a8f02229be41efb047bd8f883ba799-59258264-451c-4459-8c09-75d7d721219a-7112
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SettingsRequests\utc.app
and so on

Other valuable registry values for the Windows 10 Telemetry:
* iKey
* ver
* (device)localID = deviceID
* devmake
* devmodel
* (user) localID
* (utc) stID
* (data) cid
* cV
* aId
* (xbox) ProductID
* (xbox) CategoryID
* (app) id
* WUDeviceID
* CallerApplicationName
* ServiceGUID
* UpdateID
* BundleID
* dpxTelemetrySessionID
* objectID
* SessionID
* clientETAG
* serverETAG
* browserID
* userinputID
* conversationGUID
* appsessionGUID
* creativeID
* (Disk C:) StorageID
* (CPU) ScriptID
* (CPU) AssertionID
* (PnP) DeviceInstanceID
"""


class TelemetryFingerprint:
    """
    Windows 10 telemetry IDs
    """
    def __init__(self):
        self.device_id_guid = ("{%s}" % str(uuid.uuid4()))

    def random_device_id_guid(self):
        """
        :return: Telemetry Device ID GUID
        """
        return self.device_id_guid
