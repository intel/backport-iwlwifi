#!/usr/bin/env python3

from enum import IntEnum
import struct

WIFI_DOMAIN = 0x07
DMI_MAX_INDEX = 23

class AcpiType(IntEnum):
    ANY =		0x00
    INTEGER =		0x01
    STRING =		0x02
    BUFFER =		0x03
    PACKAGE =		0x04

class PlatformDataObject:
    def __bytes__(self):
        assert False, "must override"

    def __len__(self):
        return len(bytes(self))

class AcpiInteger(PlatformDataObject):
    type = AcpiType.INTEGER

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        return struct.pack('>BQ', self.type, self.value)

class AcpiPackage(PlatformDataObject):
    type = AcpiType.PACKAGE

    def __init__(self, *objects):
        self.objects = objects

    def __bytes__(self):
        data = [struct.pack('>BI', self.type, len(self.objects))]

        for obj in self.objects:
            data.append(_acpi_to_bytes(obj))

        return b''.join(data)

class AcpiDsmGuid(PlatformDataObject):
    def __init__(self, guid, *functions):
        assert isinstance(guid, bytes)
        assert len(guid) == 16

        self.guid = guid
        self.functions = functions

    def __bytes__(self):
        data = []

        for function in self.functions:
            # add one guid per function to make parsing easier in the driver
            data.append(self.guid)
            data.append(bytes(function))

        return b''.join(data)

class AcpiDsmFunction(PlatformDataObject):
    def __init__(self, rev, func, obj):
        assert isinstance(rev, int)
        assert isinstance(func, int)

        self.rev = rev
        self.func = func
        self.obj = obj

    def __bytes__(self):
        data = []

        data.append(self.rev.to_bytes(8, "big"))

        data.append(self.func.to_bytes(8, "big"))

        data.append(_acpi_to_bytes(self.obj))

        return b''.join(data)

def acpi_method(method, package):
    if isinstance(method, str):
        method = method.encode('ascii')
    assert isinstance(method, bytes)
    assert len(method) == 4
    return struct.pack('>4sI', method, len(package)) + bytes(package)

def _acpi_to_bytes(obj):
    if isinstance(obj, int):
        obj = AcpiInteger(obj)
    assert isinstance(obj, PlatformDataObject)
    return bytes(obj)

def acpi_dsm(*guids):
    method = '_DSM'.encode('ascii')
    data = []

    for guid in guids:
        assert isinstance(guid, AcpiDsmGuid)
        data.append(bytes(guid))

    return struct.pack('>4sI', method, len(b''.join(data))) + b''.join(data)

def efi_var(name, data):
    assert isinstance(data, bytes)
    assert isinstance(name, str)
    # check that it's pure ASCII
    name.encode('ascii')

    guid = bytes([0x2f, 0xaf, 0xda, 0x92,
                  0x2b, 0xc0,
                  0x5b, 0x45,
                  0xb2, 0xec, 0xf5, 0xa3,
                  0x59, 0x4f, 0x4a, 0xea])

    encname = name.encode('utf-16le')
    assert len(encname) <= 1024
    key = encname + b"\x00" * (1024 - len(encname)) + guid
    objcontents = key + data
    return struct.pack(">4sI", b"\x01EFI", len(objcontents)) + objcontents

def dmi_data(index, value):
   assert isinstance(index, int) and index in range(1, DMI_MAX_INDEX)
   assert isinstance(value, str)

   data = index.to_bytes(1, 'big') + value.encode('ascii')

   return struct.pack(">4sI", b"\x01DMI", len(data)) + data

wrdd_wifi = AcpiPackage(AcpiInteger(WIFI_DOMAIN), AcpiInteger(0x5a5a))
wrdd_package = AcpiPackage(AcpiInteger(0), wrdd_wifi)
wrdd_method = acpi_method("WRDD", wrdd_package)

wrds_wifi = AcpiPackage(WIFI_DOMAIN, 1,
                        # Chain 1 -- 11 subbands
                        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                        0x11, 0x11, 0x11,
                        # Chain 2 -- 11 subbands
                        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                        0x22, 0x22, 0x22,
                        # Chain 3 -- 11 subbands
                        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                        0x33, 0x33, 0x33,
                        # Chain 4 -- 11 subbands
                        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                        0x44, 0x44, 0x44)

wrds_package = AcpiPackage(2, wrds_wifi)
wrds_method = acpi_method("WRDS", wrds_package)

acpi_int = AcpiInteger(0x1122334455667788)

package = AcpiPackage(acpi_int, AcpiInteger(0xaabbccddeeffeedd), AcpiPackage(0xdeadbeef0f000f00, acpi_int))

wifi_guid = bytes([0xF2, 0x12, 0x02, 0xBF, 0x8F, 0x78, 0x4D, 0xC6,  # this line is be32, be16, be16
		   0xA5, 0xB3, 0x1F, 0x73, 0x8E, 0x28, 0x5A, 0xDE]) # and these are all u8

dsm = acpi_dsm(AcpiDsmGuid(wifi_guid,
                           AcpiDsmFunction(0, 1, 0xdeadbeef0badcafe),
                           AcpiDsmFunction(1, 2, 0xffeeddccbbaa9988)))

ppag_wifi = AcpiPackage(WIFI_DOMAIN,
                        0x1, # flags, bit 0 = enable for ETSI
                        0x8, 0xf, 0xf, 0xf, 0xf,
                        0x8, 0xf, 0xf, 0xf, 0xf)

ppag_method = acpi_method("PPAG", AcpiPackage(0, ppag_wifi))

outfile = open("iwlwifi-platform.dat", "wb")
outfile.write(wrdd_method)
outfile.write(wrds_method)
outfile.write(dsm)
outfile.write(ppag_method)
outfile.write(efi_var("UefiCnvWlanOemSignedPnvm", b"asdf"))
outfile.write(dmi_data(6, "HP"))
outfile.close()
