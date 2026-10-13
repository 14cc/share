#!/usr/bin/env python3
"""Checks Share's recognition rules.
Set SHARE_FIXTURES to a folder of <release>/misd and <release>/wifid files to
also check real daemons."""
from pathlib import Path
import os, struct, subprocess, tempfile

root = Path(__file__).resolve().parents[1]
fixtures = Path(os.environ['SHARE_FIXTURES']) if 'SHARE_FIXTURES' in os.environ else None

# release: (state gate offset, register) for misd; channel lists in wifid
MISD = {'ios12': (0x1182c, 24), 'ios14ipad': (0x11bb8, 25), 'ios15': (0x120a8, 25), 'ios16': (0x141b4, 25),
        'ios17': (0x137d8, 25), 'ios17ipad': (0x14308, 25),
        'ios18ipad': (0x13964, 27)}
# iOS 18 Settings: __text and __const (file offset, address, size); the
# cellular-data, personal-hotspot and swift_getKeyPath stubs; the expected
# cellular-data load, the personal-hotspot pattern; __got (address, size).
SETTINGS = {'ios18ipad': ((0x3b88, 0x100003b88, 0x10d81c), (0x1155d0, 0x1001155d0, 0x9bd8),
                          (0x1001139d8, 0x100113a2c, 0x100114098), 0x10002b264, 0x100116cb8,
                          (0x100154000, 0x3830))}
WIFID = {'ios12': 1, 'ios14ipad': 0, 'ios15': 0, 'ios16': 0, 'ios17': 0, 'ios18ipad': 0}

CHECK = r'''#include "share_support.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static const char *sig = "i24@0:8^{mis_ctinterface_tethering_status=BBBI{mis_ctinterface_ct_conn_status=ii[16c]}}16";
static void rules(void) {
    for (int ok = 0; ok < 2; ok++) for (int local = 0; local < 2; local++) for (uint64_t v = 198; v < 207; v++) {
        assert(share_local_mode("opMode", v, local, ok) == ((ok && local && (v == 200 || v == 201)) ? 203 : v));
        assert(share_local_mode("bridgeType", v, local, ok) == v);
        assert(share_local_mode(NULL, v, local, ok) == v);
    }
    uint32_t w[] = {0x321e1fe8, 0x1a808118, 0x321e1fe8, 0x1a808118};
    size_t site; int dest;
    assert(share_patch_sites(w, 4, &site, &dest) == 2);
    assert(share_patch_sites(w, 0, &site, &dest) == 0);
    assert(share_patched_instruction(25) == 0x2a0003f9);
    uint32_t gate[] = {0x0a190309, 0x6a08013f, 0x52807f88, 0x1a880509};
    uint32_t patched[4];
    assert(share_request_sites(gate, 4, &site, patched) == 1 && site == 0);
    assert(patched[0] == 0x6a080309 && patched[1] == 0x52807f88 && patched[2] == 0x0b090509 && patched[3] == 0xd503201f);
    gate[3] = 0x1a881509;
    assert(share_request_sites(gate, 4, &site, patched) == 0);
    uint32_t ios12[] = {0xd2800001, 0x14000001}, ios17[] = {0xd2800001, 0x17fffdb4}, other[] = {0xd503237f, 0x14000001};
    assert(share_answer_branch(ios12) == 4);
    assert(share_answer_branch(ios17) == -0x930);
    assert(share_answer_branch(other) == 0);
    assert(share_tethering_signature(sig));
    assert(!share_tethering_signature("v24@0:8^{mis_ctinterface_tethering_status=BBBI{mis_ctinterface_ct_conn_status=ii[16c]}}16"));
    assert(!share_tethering_signature("i24@0:8^{mis_ctinterface_tethering_status=BBBQ{mis_ctinterface_ct_conn_status=ii[16c]}}16"));
    assert(!share_tethering_signature(NULL));
    assert(share_data_plan_signature("i24@0:8^B16"));
    assert(!share_data_plan_signature("v24@0:8^B16"));
    assert(!share_data_plan_signature("i24@0:8@16"));
    assert(!share_data_plan_signature(NULL));

    uint32_t load[2];
    share_x0_load(0x100002000, 0x100001ff8, load);
    assert(share_x0_address(load, 0x100002000) == 0x100001ff8);
    share_x0_load(0x10002b264, 0x100116cb8, load);
    assert(load[0] == 0xf0000740 && load[1] == 0x9132e000);
    assert(share_x0_address(load, 0x10002b264) == 0x100116cb8);
    uint32_t out[3];
    struct share_channel all[] = {{1, 6, 0x0a}, {1, 36, 0x12}, {1, 40, 0x12}, {1, 44, 0x12}, {1, 52, 0x112}};
    assert(share_pick_5ghz(all, 5, out) == 3 && out[0] == 36 && out[1] == 40 && out[2] == 44);
    struct share_channel some[] = {{1, 11, 0x0a}, {1, 44, 0x12}, {1, 100, 0x112}};
    assert(share_pick_5ghz(some, 3, out) == 1 && out[0] == 44 && out[2] == 44);
    struct share_channel dfs[] = {{1, 36, 0x112}, {1, 52, 0x112}};
    assert(share_pick_5ghz(dfs, 2, out) == 0);
    assert(share_pick_5ghz(all, 0, out) == 0);
}
int main(int argc, char **argv) {
    if (argc == 1) { rules(); return 0; }
    FILE *f = fopen(argv[2], "rb"); assert(f);
    fseek(f, 0, SEEK_END); size_t n = ftell(f); rewind(f);
    void *b = malloc(n); assert(fread(b, 1, n, f) == n); fclose(f);
    if (argv[1][0] == 'w') { size_t offset; printf("%u\n", share_channel_lists(b, n, &offset)); return 0; }
    if (argv[1][0] == 's') {  /* text off/vm/size, const off/vm/size, data/hotspot/keypath stubs */
        unsigned long long v[9];
        for (int i = 0; i < 9; i++) v[i] = strtoull(argv[3 + i], NULL, 16);
        const uint32_t *text = (const uint32_t *)((char *)b + v[0]);
        uint64_t data = share_capability_getter(text, v[2] / 4, v[1], v[6]);
        uint64_t hotspot = share_capability_getter(text, v[2] / 4, v[1], v[7]);
        uint64_t data_ref = share_keypath_reference((const uint8_t *)b + v[3], v[5], v[4], data);
        uint64_t hotspot_ref = share_keypath_reference((const uint8_t *)b + v[3], v[5], v[4], hotspot);
        size_t site = 0; uint64_t pattern = 0; uint32_t load[2] = {0};
        unsigned found = share_hotspot_requirement(text, v[2] / 4, v[1], v[8], data_ref, hotspot_ref, &site, &pattern);
        share_x0_load(v[1] + site * 4, pattern, load);
        uint64_t slot = share_stub_slot((const uint32_t *)((char *)b + v[6] - v[1] + v[0]), v[6]);
        printf("%u %llx %llx %x %x %llx\n", found, (unsigned long long)(v[1] + site * 4), (unsigned long long)pattern,
               load[0], load[1], (unsigned long long)slot);
        return 0;
    }
    size_t site = 0; int dest = 0;
    unsigned count = share_patch_sites(b, n / 4, &site, &dest);
    size_t request = 0; uint32_t patched[4] = {0};
    unsigned requests = share_request_sites(b, n / 4, &request, patched);
    printf("%u %zu %d %u %d %u %zu %u\n", count, site * 4, dest, share_mode_tables(b, n), share_contains(b, n, "opMode"), requests, request * 4, patched[2]);
    return 0;
}'''

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / 'check.c').write_text(CHECK)
    subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-I', str(root / 'src'),
                    str(tmp / 'check.c'), '-o', str(tmp / 'check')], check=True)
    subprocess.run([str(tmp / 'check')], check=True)
    print('PASS state gate, mode, cellular check and 5 GHz channel rules')
    run = lambda kind, path: subprocess.check_output([str(tmp / 'check'), kind, str(path)]).split()
    for release, (offset, register) in MISD.items():
        path = fixtures / release / 'misd' if fixtures else None
        if not path or not path.exists():
            print('SKIP', release, 'misd'); continue
        values = list(map(int, run('m', path)))
        assert values[:5] == [1, offset, register, 1, 1], (release, values)
        print('    request gate', values[5], hex(values[6]) if values[5] else '')
        doubled = tmp / 'doubled'
        doubled.write_bytes(path.read_bytes() + struct.pack('<4I', 201, 201, 202, 203))
        assert run('m', doubled)[3] == b'2'
        print('PASS', release, 'misd recognized; a duplicate mode table is rejected')
    for release, (text, const, stubs, expected, pattern, got) in SETTINGS.items():
        path = fixtures / release / 'Preferences' if fixtures else None
        if not path or not path.exists():
            print('SKIP', release, 'Settings'); continue
        args = [hex(x) for x in (*text, *const, *stubs)]
        found, site, loaded, adrp, add, slot = subprocess.check_output([str(tmp / 'check'), 's', str(path), *args]).split()
        assert int(found) == 1 and int(site, 16) == expected and int(loaded, 16) == pattern, (release, found, site, loaded)
        # The new pair must equal the hotspot requirement's own adrp/add.
        code = path.read_bytes()
        hotspot_add = struct.unpack('<I', code[expected - text[1] + text[0] + 0x2c:][:4])[0]
        assert int(add, 16) == hotspot_add, (release, add, hex(hotspot_add))
        assert int(adrp, 16) == struct.unpack('<I', code[expected - text[1] + text[0]:][:4])[0]
        assert got[0] <= int(slot, 16) < got[0] + got[1], (release, slot)
        print('PASS', release, 'Settings hotspot row cellular-data requirement found')
    for release, lists in WIFID.items():
        path = fixtures / release / 'wifid' if fixtures else None
        if not path or not path.exists():
            print('SKIP', release, 'wifid'); continue
        assert int(run('w', path)[0]) == lists, release
        print('PASS', release, 'wifid', 'has the 2.4 GHz list' if lists else 'picks its band itself')
