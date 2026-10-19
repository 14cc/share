/* Share: Apple's Personal Hotspot without a SIM.
 *
 * In misd it removes the cellular requirement and asks for Apple's local
 * network mode with DHCP; Apple still creates the network. In wifid, on
 * releases with a fixed 2.4 GHz hotspot channel list, it offers 5 GHz
 * channels when the Wi-Fi driver allows them here. On Wi-Fi-only iPads and
 * cellular devices without a SIM it also skips misd's wait for a carrier and
 * lists Personal Hotspot in Settings.
 *
 * Anything unrecognized is left untouched. When something goes wrong, a
 * report is written once to Documents/Share-Report.json. */
#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#ifdef SHARE_ROOTHIDE
#include <glob.h>
#endif
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include "share_support.h"

#ifndef SHARE_VERSION
#error "SHARE_VERSION is set by build.sh"
#endif

#define SHARE_DIR "/var/mobile/Library/Share"
#define SHARE_REPORTED SHARE_DIR "/reported"
#define SHARE_RADIO SHARE_DIR "/radio.json"
#define SHARE_STATUS SHARE_DIR "/status.json"
#define SHARE_REPORT "/var/mobile/Documents/Share-Report.json"
#define MIS_KEY CFSTR("com.apple.MobileInternetSharing")
#define MIS_STATE_RESET 1020
#define MIS_STATE_RESETTING 1021
#define MIS_STATE_OFF 1022
#define MIS_STATE_ON 1023
#define MIS_SETTINGS "/var/mobile/Library/Preferences/com.apple.MobileInternetSharing.plist"
#define MOBILE_UID 501

extern const char *getprogname(void);

static dispatch_queue_t queue;

/* ── System configuration store ───────────────────────────────────
 * Private on iOS, so resolved at runtime. misd publishes the hotspot state
 * here; Settings shows Personal Hotspot when State > 1021. */
typedef void (*store_callback)(CFTypeRef, CFArrayRef, void *);
static CFTypeRef store;
static CFPropertyListRef (*store_copy)(CFTypeRef, CFStringRef);

static void watch_store(store_callback callback) {
    void *sc = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    CFTypeRef (*create)(CFAllocatorRef, CFStringRef, store_callback, void *) = sc ? dlsym(sc, "SCDynamicStoreCreate") : NULL;
    Boolean (*keys)(CFTypeRef, CFArrayRef, CFArrayRef) = sc ? dlsym(sc, "SCDynamicStoreSetNotificationKeys") : NULL;
    Boolean (*dispatch)(CFTypeRef, dispatch_queue_t) = sc ? dlsym(sc, "SCDynamicStoreSetDispatchQueue") : NULL;
    store_copy = sc ? dlsym(sc, "SCDynamicStoreCopyValue") : NULL;
    store = create ? create(NULL, CFSTR("Share"), callback, NULL) : NULL;
    if (!store || !keys || !dispatch) return;
    keys(store, (__bridge CFArrayRef)@[(__bridge NSString *)MIS_KEY], NULL);
    dispatch(store, queue);
}

static NSDictionary *hotspot_state(void) {
    id value = store && store_copy ? CFBridgingRelease(store_copy(store, MIS_KEY)) : nil;
    return [value isKindOfClass:[NSDictionary class]] ? value : @{};
}

/* ── Hooking framework ─────────────────────────────────────────────
 * Substrate, libhooker and ElleKit each expose some of these. */
static NSString *patch_method = @"none", *hook_method = @"none";

#ifdef SHARE_ROOTHIDE
/* RootHide has no /var/jb: the jailbreak lives in a per-device random
 * .jbroot-XXXXXXXXXXXXXXXX directory, found from this dylib's own path or
 * by looking in the app bundle container. */
static const char *jbroot(void) {
    static char root[PATH_MAX];
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Dl_info info;
        const char *marker;
        if (dladdr((const void *)jbroot, &info) && info.dli_fname && (marker = strstr(info.dli_fname, "/.jbroot-"))) {
            const char *end = strchr(marker + 1, '/');
            size_t length = end ? (size_t)(end - info.dli_fname) : strlen(info.dli_fname);
            if (length < sizeof root) { memcpy(root, info.dli_fname, length); root[length] = 0; return; }
        }
        static const char *patterns[] = {"/var/containers/Bundle/Application/.jbroot-*",
            "/private/var/containers/Bundle/Application/.jbroot-*", NULL};
        for (const char **pattern = patterns; !root[0] && *pattern; pattern++) {
            glob_t found;
            if (glob(*pattern, 0, NULL, &found) == 0) {
                for (size_t i = 0; !root[0] && i < found.gl_pathc; i++) {
                    char lib[PATH_MAX];
                    struct stat st;
                    snprintf(lib, sizeof lib, "%s/usr/lib", found.gl_pathv[i]);
                    if (!stat(lib, &st) && S_ISDIR(st.st_mode)) strlcpy(root, found.gl_pathv[i], sizeof root);
                }
            }
            globfree(&found);
        }
    });
    return root;
}
#endif

static void *hook_symbol(const char *name) {
    static const char *libraries[] = {
        "/usr/lib/libellekit.dylib", "/var/jb/usr/lib/libellekit.dylib",
        "/usr/lib/libsubstrate.dylib", "/var/jb/usr/lib/libsubstrate.dylib",
        "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        "/usr/lib/libhooker.dylib", "/var/jb/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstitute.dylib", "/var/jb/usr/lib/libsubstitute.dylib", NULL};
    void *symbol = dlsym(RTLD_DEFAULT, name);
    for (const char **path = libraries; !symbol && *path; path++) {
        if (access(*path, R_OK)) continue;
        void *library = dlopen(*path, RTLD_NOW);
        if (library) symbol = dlsym(library, name);
    }
#ifdef SHARE_ROOTHIDE
    const char *root = jbroot();
    for (const char **path = libraries; !symbol && root[0] && *path; path++) {
        if (!strncmp(*path, "/var/jb/", 8)) continue;
        char full[PATH_MAX];
        snprintf(full, sizeof full, "%s%s", root, *path);
        if (access(full, R_OK)) continue;
        void *library = dlopen(full, RTLD_NOW);
        if (library) symbol = dlsym(library, name);
    }
#endif
    return symbol;
}

static BOOL write_instruction(void *address, uint32_t value) {
    struct { void *destination; const void *data; size_t size; void *options; } patch = {address, &value, sizeof value, NULL};
    void (*ms_memory)(void *, const void *, size_t) = hook_symbol("MSHookMemory");
    int (*lh_memory)(void *, int) = hook_symbol("LHPatchMemory");
    if (ms_memory) ms_memory(address, &value, sizeof value);
    if (*(volatile uint32_t *)address == value) { patch_method = @"MSHookMemory"; return YES; }
    if (lh_memory) lh_memory(&patch, 1);
    if (*(volatile uint32_t *)address == value) { patch_method = @"LHPatchMemory"; return YES; }
    vm_address_t page = (vm_address_t)address & ~(vm_address_t)(vm_page_size - 1);
    if (vm_protect(mach_task_self(), page, vm_page_size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return NO;
    *(volatile uint32_t *)address = value;
    sys_icache_invalidate(address, sizeof value);
    vm_protect(mach_task_self(), page, vm_page_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    if (*(volatile uint32_t *)address != value) return NO;
    patch_method = @"vm_protect";
    return YES;
}

static BOOL write_instructions(void *address, const uint32_t *values, size_t count) {
    for (size_t i = 0; i < count; i++)
        if (!write_instruction((uint32_t *)address + i, values[i])) return NO;
    return YES;
}

/* Wi-Fi-only models have no baseband node in their device tree. */
static BOOL has_baseband(void) {
    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    mach_port_t (*from_path)(mach_port_t, const char *) = iokit ? dlsym(iokit, "IORegistryEntryFromPath") : NULL;
    kern_return_t (*release)(mach_port_t) = iokit ? dlsym(iokit, "IOObjectRelease") : NULL;
    if (!from_path || !release) return YES;
    mach_port_t entry = from_path(MACH_PORT_NULL, "IODeviceTree:/baseband");
    if (entry == MACH_PORT_NULL) return NO;
    release(entry);
    return YES;
}

/* misd restores its saved state at launch and skips the request gate when
 * that state is already AUTH_UNKNOWN (1021), so a device that once stopped
 * there (any build without the request-gate patch) stays there. Start such a
 * device from RESET instead; misd reads the file after this constructor. */
static void reset_saved_state(void) {
    NSData *data = [NSData dataWithContentsOfFile:@MIS_SETTINGS];
    if (!data) return;
    NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
    NSMutableDictionary *settings = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListMutableContainers format:&format error:NULL];
    if (![settings isKindOfClass:[NSMutableDictionary class]] ||
        [settings[@"State"] intValue] != MIS_STATE_RESETTING) return;
    struct stat info;
    if (stat(MIS_SETTINGS, &info) != 0) return;
    settings[@"State"] = @(MIS_STATE_RESET);
    NSData *updated = [NSPropertyListSerialization dataWithPropertyList:settings format:format options:0 error:NULL];
    if (![updated writeToFile:@MIS_SETTINGS atomically:YES]) return;
    chown(MIS_SETTINGS, info.st_uid, info.st_gid);
    chmod(MIS_SETTINGS, info.st_mode & 07777);
}

static BOOL hook_function(void *target, void *replacement, void **original) {
    struct { void *function, *replacement, *original, *options; } hook = {target, replacement, original, NULL};
    void (*ms_function)(void *, void *, void **) = hook_symbol("MSHookFunction");
    int (*lh_functions)(void *, int) = hook_symbol("LHHookFunctions");
    if (ms_function) ms_function(target, replacement, original);
    if (*original) { hook_method = @"MSHookFunction"; return YES; }
    if (lh_functions && lh_functions(&hook, 1) == 1 && *original) { hook_method = @"LHHookFunctions"; return YES; }
    return NO;
}

/* ── Shared files ──────────────────────────────────────────────────
 * Written by root daemons, owned by mobile so Filza and Files can read them. */
static void write_mobile_file(const char *path, NSData *data) {
    mkdir(SHARE_DIR, 0755);
    chown(SHARE_DIR, MOBILE_UID, MOBILE_UID);
    if (![data writeToFile:@(path) atomically:YES]) return;
    chown(path, MOBILE_UID, MOBILE_UID);
    chmod(path, 0644);
}

static NSData *json(id object) {
    return [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:NULL];
}

/* ════════════════════════════════════════════════════════════════
 * misd
 * ════════════════════════════════════════════════════════════════ */
struct share_ct_status {
    _Bool carrier, auth, available;
    unsigned max_hosts;
    struct { int state, index; char name[16]; } conn;
};

static int (*ct_original)(id, SEL, struct share_ct_status *);
static int (*plan_original)(id, SEL, BOOL *);
static uint64_t (*data_original)(void *, Boolean *);
static int (*carrier_original)(int, Boolean *);
static uint64_t (*mode_original)(void *, const char *);
static CFStringRef (*sim_status)(void);
static CFStringRef *sim_ready;
static _Atomic int local_mode, tethering_result = -1, carrier_result = -1, carrier_overrides;
static BOOL compatible, ct_backend, wifi_only;
static NSString *failure = @"", *signature = @"absent", *plan_signature = @"absent";
static NSMutableDictionary *binary;

static void *load_telephony(void) {
    void *telephony = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
    sim_status = telephony ? dlsym(telephony, "CTSIMSupportGetSIMStatus") : NULL;
    sim_ready = telephony ? dlsym(telephony, "kCTSIMSupportSIMStatusReady") : NULL;
    return telephony;
}

/* No usable SIM: none, locked, or no baseband at all. */
static int sim_unusable(void) {
    if (wifi_only) return 1;
    CFStringRef status = sim_status ? sim_status() : NULL;
    return !status || !sim_ready || !*sim_ready || !CFEqual(status, *sim_ready);
}

/* CoreTelephony states that no SIM is usable (not inserted, locked).
 * Unlike sim_unusable, an unanswered query does not count, so a SIM device
 * whose CoreTelephony is still starting keeps its carrier check. */
static int sim_absent(void) {
    if (wifi_only) return 1;
    CFStringRef status = sim_status ? sim_status() : NULL;
    return status && sim_ready && *sim_ready && !CFEqual(status, *sim_ready);
}

/* Without cellular service the query reports no connection, or fails on
 * Wi-Fi-only models. Both are the local case. */
static int ct_status(id self, SEL cmd, struct share_ct_status *s) {
    int result = ct_original(self, cmd, s);
    atomic_store(&tethering_result, result);
    if (!s) return result;
    int local = result != 0 || (!s->available && !s->conn.name[0]);
    atomic_store(&local_mode, local);
    if (!local || !compatible) return result;
    s->carrier = 1;
    s->auth = 1;
    return 0;
}

/* iOS 14 turns the hotspot off when the cellular data plan reads off. With no
 * cellular connection, report it on so the local network can start. */
static int plan_status(id self, SEL cmd, BOOL *enabled) {
    int result = plan_original(self, cmd, enabled);
    if (!compatible || !enabled || (result == 0 && *enabled)) return result;
    struct share_ct_status s = {0};
    int status = ct_original(self, sel_registerName("getTetheringStatus:"), &s);
    if (status == 0 && (s.available || s.conn.name[0])) return result;
    *enabled = YES;
    return 0;
}

/* iOS 12 asks CoreTelephony directly. The error sits in the upper half of the
 * returned CTError. */
static uint64_t data_status(void *connection, Boolean *enabled) {
    uint64_t result = data_original(connection, enabled);
    if (!compatible || !enabled || ((result >> 32) == 0 && *enabled) || !sim_unusable()) return result;
    *enabled = 1;
    return 0;
}

/* iOS 12 misd's own carrier check fails with 45 when CoreTelephony has no
 * data connection to tether, and misd then stays in RESET. Its side effects
 * (the host limit) still run; without a usable SIM it reports success and an
 * enabled data plan. Found by @t-klinger-cmd on an iPad mini 2 Cellular. */
static int carrier_status(int request, Boolean *enabled) {
    int result = carrier_original(request, enabled);
    atomic_store(&carrier_result, result);
    if (!compatible || !enabled || !sim_unusable()) return result;
    *enabled = 1;
    atomic_fetch_add(&carrier_overrides, 1);
    return 0;
}

static uint64_t mode_get(void *dictionary, const char *key) {
    uint64_t value = mode_original(dictionary, key);
    if (!key || strcmp(key, "opMode") || (value != 200 && value != 201)) return value;
    int local = ct_backend ? atomic_load(&local_mode) : sim_unusable();
    if (!ct_backend) atomic_store(&local_mode, local);
    return share_local_mode(key, value, local, compatible);
}

static const struct mach_header_64 *main_image(NSString **path) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE) {
            if (path) *path = @(_dyld_get_image_name(i));
            return (const void *)h;
        }
    }
    return NULL;
}

static NSString *image_uuid(const struct mach_header_64 *header) {
    const uint8_t *cursor = (const uint8_t *)(header + 1), *end = cursor + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof *command || cursor + command->cmdsize > end) break;
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command))
            return [[NSUUID alloc] initWithUUIDBytes:((const struct uuid_command *)cursor)->uuid].UUIDString;
        cursor += command->cmdsize;
    }
    return @"unknown";
}

/* The image's LC_FUNCTION_STARTS data, as mapped in __LINKEDIT. */
static const uint8_t *function_starts(const struct mach_header_64 *header, size_t *size) {
    const uint8_t *cursor = (const uint8_t *)(header + 1), *end = cursor + header->sizeofcmds;
    const struct linkedit_data_command *starts = NULL;
    const struct segment_command_64 *text = NULL, *linkedit = NULL;
    for (uint32_t i = 0; i < header->ncmds && cursor + sizeof(struct load_command) <= end; i++) {
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof *command || cursor + command->cmdsize > end) break;
        if (command->cmd == LC_FUNCTION_STARTS) starts = (const void *)cursor;
        if (command->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)cursor)->segname, "__TEXT"))
            text = (const void *)cursor;
        if (command->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)cursor)->segname, "__LINKEDIT"))
            linkedit = (const void *)cursor;
        cursor += command->cmdsize;
    }
    if (!starts || !text || !linkedit || starts->dataoff < linkedit->fileoff ||
        starts->dataoff + starts->datasize > linkedit->fileoff + linkedit->filesize) return NULL;
    *size = starts->datasize;
    return (const uint8_t *)header + (linkedit->vmaddr - text->vmaddr) + (starts->dataoff - linkedit->fileoff);
}

static void install(void) {
    NSString *path = @"";
    const struct mach_header_64 *header = main_image(&path);
    unsigned long size = 0;
    uint8_t *text = header ? getsegmentdata(header, "__TEXT", &size) : NULL;
    size_t site = 0;
    int destination = 0;
    unsigned sites = text ? share_patch_sites((const uint32_t *)text, size / 4, &site, &destination) : 0;
    unsigned tables = text ? share_mode_tables(text, size) : 0;
    size_t request_site = 0;
    uint32_t request_patch[4] = {0};
    unsigned requests = text ? share_request_sites((const uint32_t *)text, size / 4, &request_site, request_patch) : 0;
    wifi_only = !has_baseband();
    BOOL local_dhcp = text && tables == 1 && share_contains(text, size, "opMode") &&
        (share_contains(text, size, "local with dhcp mode") || share_contains(text, size, "local_with_dhcp_mode"));
    binary = [@{@"path": path, @"uuid": header ? image_uuid(header) : @"unknown",
                @"cpu": header ? @[@(header->cputype), @(header->cpusubtype & 0xff)] : @[],
                @"stateGateMatches": @(sites), @"modeTables": @(tables), @"localDHCPMode": @(local_dhcp),
                @"requestGateMatches": @(requests), @"baseband": @(!wifi_only)} mutableCopy];
    if (sites == 1) {
        binary[@"stateGateOffset"] = @((uintptr_t)(text + site * 4) - (uintptr_t)header);
        binary[@"stateGateInstruction"] = @(((uint32_t *)text)[site]);
    }

    void *telephony = load_telephony();
    Class client = objc_getClass("misCTClientSharedInstance");
    Method method = client ? class_getInstanceMethod(client, sel_registerName("getTetheringStatus:")) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (types) signature = @(types);
    ct_backend = client != Nil;
    BOOL permission = ct_backend ? share_tethering_signature(types) : (sim_status && sim_ready);
    void *mode_lookup = dlsym(RTLD_DEFAULT, "xpc_dictionary_get_uint64");

    if (!header || header->cputype != CPU_TYPE_ARM64) { failure = @"Unsupported processor"; return; }
    if (sites != 1) { failure = @"Hotspot state gate not found"; return; }
    if (!local_dhcp) { failure = @"Local hotspot mode not found"; return; }
    if (!permission) { failure = @"Cellular check not recognized"; return; }
    if (!mode_lookup) { failure = @"Hotspot mode lookup not found"; return; }
    if (!write_instruction(text + site * 4, share_patched_instruction(destination))) { failure = @"Could not patch misd"; return; }
    if (requests == 1 && sim_absent() && write_instructions(text + request_site * 4, request_patch, 4)) {
        binary[@"requestGateOffset"] = @((uintptr_t)(text + request_site * 4) - (uintptr_t)header);
        reset_saved_state();
    }
    if (!hook_function(mode_lookup, (void *)mode_get, (void **)&mode_original)) { failure = @"Hooking framework unavailable"; return; }
    if (ct_backend) ct_original = (void *)method_setImplementation(method, (IMP)ct_status);
    compatible = !ct_backend || ct_original != NULL;
    if (!compatible) { failure = @"Could not adapt the cellular check"; return; }
    void *data_check = !ct_backend && telephony ? dlsym(telephony, "_CTServerConnectionGetCellularDataIsEnabled") : NULL;
    if (data_check) hook_function(data_check, (void *)data_status, (void **)&data_original);
    size_t starts_size = 0;
    const uint8_t *starts = ct_backend ? NULL : function_starts(header, &starts_size);
    int64_t message = starts ? share_find(text, size, "carrier service is %savailable") : -1;
    uint64_t carrier = message > 0 ? share_carrier_check((const uint32_t *)text, size / 4, starts, starts_size, (uint64_t)message) : 0;
    if (carrier && hook_function(text + carrier, (void *)carrier_status, (void **)&carrier_original))
        binary[@"carrierCheckOffset"] = @(carrier);
    Method plan = ct_backend ? class_getInstanceMethod(client, sel_registerName("isDataPlanEnabled:")) : NULL;
    const char *plan_types = plan ? method_getTypeEncoding(plan) : NULL;
    if (plan_types) plan_signature = @(plan_types);
    if (share_data_plan_signature(plan_types)) plan_original = (void *)method_setImplementation(plan, (IMP)plan_status);
}

/* ── Report ───────────────────────────────────────────────────────
 * One per kind of problem, misd build and Share version. */
static NSString *sysctl_string(const char *key) {
    char buffer[256] = {0};
    size_t size = sizeof buffer;
    return sysctlbyname(key, buffer, &size, NULL, 0) == 0 ? @(buffer) : @"unavailable";
}

static NSString *sha256(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
    if (!data) return @"unavailable";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString string];
    for (unsigned i = 0; i < sizeof digest; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSDictionary *interfaces(void) {
    NSMutableDictionary *found = [NSMutableDictionary dictionary];
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return found;
    for (struct ifaddrs *i = list; i; i = i->ifa_next) {
        if (strcmp(i->ifa_name, "ap1") && strcmp(i->ifa_name, "bridge100")) continue;
        NSMutableDictionary *entry = found[@(i->ifa_name)] ?: [@{@"up": @((i->ifa_flags & IFF_UP) != 0), @"ipv4": @NO} mutableCopy];
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET) entry[@"ipv4"] = @YES;
        found[@(i->ifa_name)] = entry;
    }
    freeifaddrs(list);
    return found;
}

static NSArray *hotspot_classes(void) {
    NSMutableArray *classes = [NSMutableArray array];
    unsigned count = 0;
    Class *all = objc_copyClassList(&count);
    for (unsigned i = 0; i < count; i++) {
        const char *name = class_getName(all[i]);
        if (strncmp(name, "mis", 3) && strcmp(name, "MISManager")) continue;
        unsigned methods_count = 0;
        Method *methods = class_copyMethodList(all[i], &methods_count);
        NSMutableArray *list = [NSMutableArray array];
        for (unsigned j = 0; j < methods_count; j++) {
            const char *types = method_getTypeEncoding(methods[j]);
            [list addObject:[NSString stringWithFormat:@"%s %s", sel_getName(method_getName(methods[j])), types ?: ""]];
        }
        free(methods);
        [classes addObject:@{@"class": @(name), @"methods": list}];
    }
    free(all);
    return classes;
}

static void report(NSString *kind, NSString *detail) {
    NSString *key = [NSString stringWithFormat:@"%@ %@ %@", binary[@"uuid"] ?: @"unknown", @SHARE_VERSION, kind];
    NSString *reported = [NSString stringWithContentsOfFile:@SHARE_REPORTED encoding:NSUTF8StringEncoding error:NULL] ?: @"";
    if ([[reported componentsSeparatedByString:@"\n"] containsObject:key]) return;
    write_mobile_file(SHARE_REPORTED, [[reported stringByAppendingFormat:@"%@\n", key] dataUsingEncoding:NSUTF8StringEncoding]);

    NSMutableDictionary *hotspot = [hotspot_state() mutableCopy];
    [hotspot removeObjectsForKeys:@[@"ExternalInterfaces", @"InternalInterfaces"]];
    NSMutableDictionary *misd = [binary mutableCopy] ?: [NSMutableDictionary dictionary];
    misd[@"sha256"] = sha256(misd[@"path"] ?: @"");
    id radio = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@SHARE_RADIO] ?: [NSData data] options:0 error:NULL];
    NSDictionary *bootpd = [NSDictionary dictionaryWithContentsOfFile:@"/Library/Preferences/SystemConfiguration/bootpd.plist"];
    NSDictionary *contents = @{
        @"problem": kind, @"detail": detail, @"share": @SHARE_VERSION, @"date": NSDate.date.description,
        @"device": @{@"model": sysctl_string("hw.machine"), @"build": sysctl_string("kern.osversion"),
                     @"iOS": NSProcessInfo.processInfo.operatingSystemVersionString,
                     @"rootless": @(access("/var/jb", F_OK) == 0)},
        @"misd": misd,
        @"engine": @{@"compatible": @(compatible), @"failure": failure,
                     @"cellularCheck": ct_backend ? @"CoreTelephony" : @"SIM status",
                     @"tetheringStatusSignature": signature, @"tetheringStatusResult": @(atomic_load(&tethering_result)),
                     @"dataPlanSignature": plan_signature, @"dataPlanHook": @(plan_original != NULL || data_original != NULL),
                     @"carrierCheckHook": @(carrier_original != NULL), @"carrierCheckResult": @(atomic_load(&carrier_result)),
                     @"carrierCheckOverrides": @(atomic_load(&carrier_overrides)),
                     @"localMode": @(atomic_load(&local_mode)), @"patch": patch_method, @"hook": hook_method,
                     @"hookFrameworks": @{@"MSHookFunction": @(hook_symbol("MSHookFunction") != NULL),
                                          @"MSHookMemory": @(hook_symbol("MSHookMemory") != NULL),
                                          @"LHHookFunctions": @(hook_symbol("LHHookFunctions") != NULL)}},
        @"hotspot": hotspot, @"interfaces": interfaces(), @"radio": radio ?: @{},
        @"dhcp": @{@"configured": @(bootpd != nil), @"enabled": [bootpd[@"dhcp_enabled"] description] ?: @"absent"},
        @"hotspotClasses": hotspot_classes(),
        @"privacy": @"No passwords, network names, MAC addresses, client names or cellular identifiers."};
    write_mobile_file(SHARE_REPORT, json(contents));
}

/* Settings shows Personal Hotspot only from State > 1021; misd also
 * publishes an error number when the hotspot fails. iOS 14 publishes OFF with
 * error 45 and no reason, so an error counts only when ON or with a reason. */
static BOOL check_pending;

static void check_hotspot(void) {
    check_pending = NO;
    NSDictionary *state = hotspot_state();
    if (!state.count) return;
    if ([state[@"State"] intValue] <= MIS_STATE_RESETTING)
        report(@"hotspot unavailable", [NSString stringWithFormat:@"misd stays in state %@", state[@"State"]]);
    else if ([state[@"Errnum"] intValue] != 0 &&
             ([state[@"State"] intValue] == MIS_STATE_ON || [state[@"Reason"] intValue] != 0))
        report(@"hotspot error", [NSString stringWithFormat:@"misd reported error %@", state[@"Errnum"]]);
}

/* What Share did in misd and the last hotspot states, readable in Filza
 * without scutil. Rewritten on every change. */
static void write_status(void) {
    static NSMutableArray *history;
    if (!history) history = [NSMutableArray array];
    NSDictionary *state = hotspot_state();
    /* misd also republishes when only the host count changes. */
    NSDictionary *entry = @{@"State": state[@"State"] ?: @0, @"Reason": state[@"Reason"] ?: @0,
                            @"Errnum": state[@"Errnum"] ?: @0};
    NSMutableDictionary *last = [history.lastObject mutableCopy];
    [last removeObjectForKey:@"date"];
    if (state.count && ![last isEqual:entry]) {
        NSMutableDictionary *dated = [entry mutableCopy];
        dated[@"date"] = NSDate.date.description;
        [history addObject:dated];
        if (history.count > 8) [history removeObjectAtIndex:0];
    }
    write_mobile_file(SHARE_STATUS, json(@{
        @"share": @SHARE_VERSION, @"misd": binary[@"uuid"] ?: @"unknown",
        @"compatible": @(compatible), @"failure": failure, @"patch": patch_method, @"hook": hook_method,
        @"localMode": @(atomic_load(&local_mode)), @"wifiOnly": @(wifi_only),
        @"carrierCheckOverrides": @(atomic_load(&carrier_overrides)), @"states": history}));
}

static void misd_state_changed(CFTypeRef s, CFArrayRef keys, void *info) {
    write_status();
    if (check_pending) return;
    check_pending = YES;
    /* Startup passes through the unavailable states; judge once settled. */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC), queue, ^{ @autoreleasepool { @try { check_hotspot(); } @catch (id e) {} } });
}

static void start_misd(void) {
    @try { install(); }
    @catch (id exception) { failure = [exception description] ?: @"Startup failed"; }
    dispatch_async(queue, ^{
        @autoreleasepool {
            @try {
                write_status();
                if (!compatible) { report(@"unsupported", failure); return; }
                watch_store(misd_state_changed);
                misd_state_changed(NULL, NULL, NULL);
            } @catch (id exception) {}
        }
    });
}

/* ════════════════════════════════════════════════════════════════
 * wifid
 * ════════════════════════════════════════════════════════════════
 * Older wifid starts the hotspot on one of {1, 6, 11}. The list lives in
 * writable data, so it is swapped for 5 GHz channels the driver currently
 * allows; newer wifid has no such list and picks the band itself. */
struct apple80211req { char name[IFNAMSIZ]; int type; int value; uint32_t length; void *data; };
struct apple80211_channels { uint32_t version, count; struct share_channel channels[64]; };
#define SIOCGA80211 _IOWR('i', 201, struct apple80211req)
#define APPLE80211_IOC_SUPPORTED_CHANNELS 27

static uint32_t *channel_list;

static unsigned driver_channels(struct apple80211_channels *result) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct apple80211req request = {.name = "en0", .type = APPLE80211_IOC_SUPPORTED_CHANNELS,
                                    .length = sizeof *result, .data = result};
    memset(result, 0, sizeof *result);
    result->version = 1;
    int ok = ioctl(fd, SIOCGA80211, &request) == 0;
    close(fd);
    return ok ? MIN(result->count, 64u) : 0;
}

static void choose_band(void) {
    struct apple80211_channels driver;
    unsigned count = driver_channels(&driver);
    uint32_t five[3];
    unsigned picked = share_pick_5ghz(driver.channels, count, five);
    memcpy(channel_list, picked ? five : share_stock_channels, sizeof share_stock_channels);
    NSMutableArray *offered = [NSMutableArray array];
    for (unsigned i = 0; i < count; i++) [offered addObject:@[@(driver.channels[i].channel), @(driver.channels[i].flags)]];
    write_mobile_file(SHARE_RADIO, json(@{@"hotspotChannels": @[@(channel_list[0]), @(channel_list[1]), @(channel_list[2])],
                                          @"driverChannels": offered}));
}

static void wifid_state_changed(CFTypeRef s, CFArrayRef keys, void *info) {
    @autoreleasepool { @try { choose_band(); } @catch (id e) {} }
}

static void start_wifid(void) {
    const struct mach_header_64 *header = main_image(NULL);
    unsigned long size = 0;
    uint8_t *data = header ? getsegmentdata(header, "__DATA", &size) : NULL;
    size_t offset = 0;
    if (!data || share_channel_lists(data, size, &offset) != 1) return;
    channel_list = (uint32_t *)(data + offset);
    dispatch_async(queue, ^{
        /* The region can change after launch; recheck whenever the hotspot
         * state does, before wifid starts the access point. */
        watch_store(wifid_state_changed);
        wifid_state_changed(NULL, NULL, NULL);
    });
}

/* ── Settings ─────────────────────────────────────────────────────
 * Wi-Fi-only models lack the personal-hotspot capability, so Settings hides
 * Personal Hotspot. MGCopyAnswer is `mov x1, #0; b answer`, and
 * MGGetBoolAnswer calls the same answer function, so one hook covers both.
 * iOS 18's MobileGestalt_get_personalHotspotCapability asks by the key's
 * hashed name. */
static CFTypeRef (*answer_original)(CFStringRef, void *);

static BOOL hotspot_key(CFStringRef key) {
    return key && CFGetTypeID(key) == CFStringGetTypeID() &&
        (CFEqual(key, CFSTR("personal-hotspot")) || CFEqual(key, CFSTR("wlxZYdEZITDTzgs/OnnV+Q")));
}

/* MGGetBoolAnswer passes a pointer the answer function fills with the value's
 * type, so the original always runs and only the value is replaced. */
static CFTypeRef answer(CFStringRef key, void *options) {
    CFTypeRef value = answer_original(key, options);
    if (!value || CFGetTypeID(value) != CFBooleanGetTypeID() || !hotspot_key(key))
        return value;
    CFRelease(value);
    return CFRetain(kCFBooleanTrue);
}

/* The Personal Hotspot row also requires cellular-data. Settings.plist is
 * edited as it loads, for that row only, so no other cellular screen appears. */
static id (*plist_original)(NSDictionary *, id, id, NSString *, NSBundle *, void *, void *, id, void *);

static id plist_specifiers(NSDictionary *plist, id parent, id target, NSString *name, NSBundle *bundle,
                           void *title, void *identifier, id list, void *controllers) {
    NSArray *items = [plist isKindOfClass:[NSDictionary class]] ? plist[@"items"] : nil;
    NSUInteger index = [items isKindOfClass:[NSArray class]] ?
        [items indexOfObjectPassingTest:^BOOL(id item, NSUInteger i, BOOL *stop) {
            return [item isKindOfClass:[NSDictionary class]] &&
                [item[@"id"] isEqual:@"INTERNET_TETHERING"] && item[@"requiredCapabilities"];
        }] : NSNotFound;
    if (index != NSNotFound) {
        NSMutableDictionary *item = [items[index] mutableCopy];
        [item removeObjectForKey:@"requiredCapabilities"];
        NSMutableArray *edited = [items mutableCopy];
        edited[index] = item;
        NSMutableDictionary *copy = [plist mutableCopy];
        copy[@"items"] = edited;
        plist = copy;
    }
    return plist_original(plist, parent, target, name, bundle, title, identifier, list, controllers);
}

/* Preferences checks a row's capabilities in one call. Rows that need
 * personal-hotspot are the Personal Hotspot ones. */
static BOOL (*capabilities_original)(NSArray *);

static BOOL capabilities(NSArray *required) {
    if ([required isKindOfClass:[NSArray class]] && [required containsObject:@"personal-hotspot"]) return YES;
    return capabilities_original(required);
}

/* iOS 12 misd leaves RESET only when a client asks for a state; on cellular
 * models a carrier event does it. A restored Wi-Fi-only iPad, or a cellular
 * one without a SIM, has neither, and
 * Settings hides Personal Hotspot in RESET. Ask for OFF, as the switch would. */
static void request_off(void) {
    dlopen("/System/Library/PreferenceBundles/WirelessModemSettings.bundle/WirelessModemSettings", RTLD_NOW);
    Class manager_class = objc_getClass("MISManager");
    SEL shared = sel_registerName("sharedManager"), get = sel_registerName("getState:andReason:"),
        set = sel_registerName("setState:");
    id manager = [manager_class respondsToSelector:shared] ? ((id (*)(id, SEL))objc_msgSend)(manager_class, shared) : nil;
    if (![manager respondsToSelector:get] || ![manager respondsToSelector:set]) return;
    int state = 0, reason = 0;
    ((void (*)(id, SEL, int *, int *))objc_msgSend)(manager, get, &state, &reason);
    if (state == MIS_STATE_RESET) ((void (*)(id, SEL, int))objc_msgSend)(manager, set, MIS_STATE_OFF);
}

/* iOS 18 Settings builds the row in Swift and requires cellular-data and
 * personal-hotspot. The hotspot row's cellular-data requirement is rewritten
 * to load its personal-hotspot one, so no other cellular row appears. */
static uint64_t stub_for(const struct mach_header_64 *header, const void *function) {
    const void *plain = ptrauth_strip(function, ptrauth_key_function_pointer);
    const char *names[] = {"__stubs", "__auth_stubs"};
    for (int n = 0; n < 2; n++) {
        unsigned long size = 0;
        uint8_t *data = getsectiondata(header, "__TEXT", names[n], &size);
        for (unsigned long offset = 0; data && offset + 8 <= size; offset += 4) {
            uint64_t slot = share_stub_slot((const uint32_t *)(data + offset), (uint64_t)(data + offset));
            if (slot && ptrauth_strip(*(void **)slot, ptrauth_key_asia) == plain) return (uint64_t)(data + offset);
        }
    }
    return 0;
}

static void enable_hotspot_row(void) {
    const struct mach_header_64 *header = main_image(NULL);
    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    void *data = gestalt ? dlsym(gestalt, "MobileGestalt_get_cellularDataCapability") : NULL;
    void *hotspot = gestalt ? dlsym(gestalt, "MobileGestalt_get_personalHotspotCapability") : NULL;
    void *keypath = dlsym(RTLD_DEFAULT, "swift_getKeyPath");
    if (!header || !data || !hotspot || !keypath) return;
    unsigned long text_size = 0, const_size = 0;
    uint8_t *text = getsectiondata(header, "__TEXT", "__text", &text_size);
    uint8_t *constants = getsectiondata(header, "__TEXT", "__const", &const_size);
    if (!text || !constants) return;
    const uint32_t *w = (const uint32_t *)text;
    size_t count = text_size / 4;
    uint64_t base = (uint64_t)text;
    uint64_t data_getter = share_capability_getter(w, count, base, stub_for(header, data));
    uint64_t hotspot_getter = share_capability_getter(w, count, base, stub_for(header, hotspot));
    uint64_t data_reference = data_getter ? share_keypath_reference(constants, const_size, (uint64_t)constants, data_getter) : 0;
    uint64_t hotspot_reference = hotspot_getter ? share_keypath_reference(constants, const_size, (uint64_t)constants, hotspot_getter) : 0;
    uint64_t keypath_stub = stub_for(header, keypath);
    size_t site = 0;
    uint64_t pattern = 0;
    if (!data_reference || !hotspot_reference || !keypath_stub ||
        share_hotspot_requirement(w, count, base, keypath_stub, data_reference, hotspot_reference, &site, &pattern) != 1)
        return;
    uint32_t load[2];
    share_x0_load(base + site * 4, pattern, load);
    write_instructions(text + site * 4, load, 2);
}

/* Cellular models without a SIM get no carrier event either, so they take
 * the Wi-Fi-only path too; on them the capability edits change nothing. */
static void start_settings(void) {
    wifi_only = !has_baseband();
    load_telephony();
    if (!sim_absent()) return;
    enable_hotspot_row();
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ @autoreleasepool { @try { request_off(); } @catch (id e) {} } });
    void *preferences = dlopen("/System/Library/PrivateFrameworks/Preferences.framework/Preferences", RTLD_NOW);
    void *loader = preferences ? dlsym(preferences, "SpecifiersFromPlist") : NULL;
    if (loader) hook_function(loader, (void *)plist_specifiers, (void **)&plist_original);
    void *check = preferences ? dlsym(preferences, "SystemHasCapabilities") : NULL;
    if (check) hook_function(check, (void *)capabilities, (void **)&capabilities_original);
    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    void *copy = gestalt ? dlsym(gestalt, "MGCopyAnswer") : NULL;
    /* On arm64e dlsym returns a signed pointer; read the code through a plain one. */
    const uint32_t *code = copy ? ptrauth_strip(copy, ptrauth_key_function_pointer) : NULL;
    int64_t offset = code ? share_answer_branch(code) : 0;
    if (!offset) return;
    void *target = (void *)((const char *)(code + 1) + offset);
    target = ptrauth_sign_unauthenticated(target, ptrauth_key_function_pointer, 0);
    hook_function(target, (void *)answer, (void **)&answer_original);
}

__attribute__((constructor)) static void share_init(void) {
    const char *name = getprogname();
    BOOL misd = !strcmp(name, "misd"), wifid = !strcmp(name, "wifid");
    if (!strcmp(name, "Preferences")) { start_settings(); return; }
    if (!misd && !wifid) return;
    queue = dispatch_queue_create("com.rostane.share", DISPATCH_QUEUE_SERIAL);
    @autoreleasepool {
        if (misd) start_misd();
        else start_wifid();
    }
}
