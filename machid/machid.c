//go:build darwin && !driverkit

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hidsystem/IOHIDUserDevice.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include "machid.h"
#include "_cgo_export.h"

static IOHIDUserDeviceRef device;

static void set_number(CFMutableDictionaryRef properties, CFStringRef key, int32_t value) {
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &value);
    CFDictionarySetValue(properties, key, number);
    CFRelease(number);
}

int machid_start(const uint8_t *descriptor, int descriptor_length) {
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef descriptor_data = CFDataCreate(kCFAllocatorDefault, descriptor, descriptor_length);
    CFDictionarySetValue(properties, CFSTR(kIOHIDReportDescriptorKey), descriptor_data);
    CFRelease(descriptor_data);
    set_number(properties, CFSTR(kIOHIDVendorIDKey), 0);
    set_number(properties, CFSTR(kIOHIDProductIDKey), 0);
    set_number(properties, CFSTR(kIOHIDPrimaryUsagePageKey), 0xF1D0);
    set_number(properties, CFSTR(kIOHIDPrimaryUsageKey), 0x01);
    CFDictionarySetValue(properties, CFSTR(kIOHIDTransportKey), CFSTR(kIOHIDTransportUSBValue));
    CFDictionarySetValue(properties, CFSTR(kIOHIDManufacturerKey), CFSTR("virtbw"));
    CFDictionarySetValue(properties, CFSTR(kIOHIDProductKey), CFSTR("virtbw Virtual FIDO"));
    CFDictionarySetValue(properties, CFSTR(kIOHIDSerialNumberKey), CFSTR("virtbw"));

    device = IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault, properties, 0);
    CFRelease(properties);
    if (device == NULL) {
        return -1;
    }

    dispatch_queue_t queue = dispatch_queue_create("virtbw.hid", DISPATCH_QUEUE_SERIAL);
    IOHIDUserDeviceSetDispatchQueue(device, queue);
    // The host writes CTAPHID packets as output reports.
    IOHIDUserDeviceRegisterSetReportBlock(device, ^IOReturn(IOHIDReportType type, uint32_t reportID, const uint8_t *report, CFIndex reportLength) {
        if (type == kIOHIDReportTypeOutput) {
            machidReceiveReport((void *)report, (int)reportLength);
        }
        return kIOReturnSuccess;
    });
    IOHIDUserDeviceRegisterGetReportBlock(device, ^IOReturn(IOHIDReportType type, uint32_t reportID, uint8_t *report, CFIndex *reportLength) {
        return kIOReturnUnsupported;
    });
    IOHIDUserDeviceActivate(device);
    return 0;
}

int machid_send(const uint8_t *report, int length) {
    return IOHIDUserDeviceHandleReportWithTimeStamp(device, mach_absolute_time(), report, length);
}
