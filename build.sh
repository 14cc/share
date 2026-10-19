#!/bin/sh
# Builds the rootful and rootless packages into build/.
# Needs clang, ldid and dpkg-deb, plus an iPhoneOS SDK with arm64e stubs:
#   SDK=/path/to/iPhoneOS.sdk ./build.sh
set -eu
cd "$(dirname "$0")"

sdk=${SDK:-$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || true)}
[ -d "$sdk" ] || { echo "Set SDK to an iPhoneOS SDK." >&2; exit 1; }
for tool in clang ldid dpkg-deb; do
    command -v "$tool" >/dev/null || { echo "Missing $tool." >&2; exit 1; }
done

version=$(cat VERSION)${VERSION_SUFFIX:-}
display=$(echo "$version" | sed -e 's/~alpha/ Alpha /' -e 's/~beta/ Beta /' -e 's/~rc/ RC /')

rm -rf build
mkdir -p build
# misd and wifid are arm64e on A12 and newer.
clang -isysroot "$sdk" -miphoneos-version-min=12.0 -fobjc-arc -Os -Wall -arch arm64 -arch arm64e \
    -DSHARE_VERSION="\"$display\"" -dynamiclib -o build/Share.dylib src/Share.m -framework Foundation
ldid -S build/Share.dylib
# The RootHide build also looks for ElleKit/Substrate inside the jbroot.
mkdir -p build/roothide-dylib
clang -isysroot "$sdk" -miphoneos-version-min=12.0 -fobjc-arc -Os -Wall -arch arm64 -arch arm64e \
    -DSHARE_VERSION="\"$display\"" -DSHARE_ROOTHIDE -dynamiclib -o build/roothide-dylib/Share.dylib src/Share.m -framework Foundation
ldid -S build/roothide-dylib/Share.dylib

# RootHide keeps the jailbreak in a per-device random directory, so its
# scripts find it at run time instead of using a fixed prefix.
roothide_path() {
    awk '/^PATH=/ {
        print "JBROOT=\"\""
        print "case \"$0\" in */var/lib/dpkg/info/*) JBROOT=\"${0%/var/lib/dpkg/info/*}\" ;; esac"
        print "if [ -z \"$JBROOT\" ] || [ ! -d \"$JBROOT/usr/bin\" ]; then"
        print "    JBROOT=\"\""
        print "    for d in /var/containers/Bundle/Application/.jbroot-*; do"
        print "        if [ -d \"$d/usr/bin\" ]; then JBROOT=\"$d\"; break; fi"
        print "    done"
        print "fi"
        print "PATH=\"$JBROOT/usr/bin:$JBROOT/bin:$JBROOT/usr/sbin:$JBROOT/sbin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH\""
        next } { print }' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

package() { # name prefix architecture minimum-iOS shell
    root="build/$1"
    mkdir -p "$root$2/Library/MobileSubstrate/DynamicLibraries" "$root/DEBIAN"
    dylib=build/Share.dylib
    [ "$1" = roothide ] && dylib=build/roothide-dylib/Share.dylib
    cp "$dylib" src/Share.plist "$root$2/Library/MobileSubstrate/DynamicLibraries/"
    sed -e "s|@PACKAGE_VERSION@|$version|" -e "s|@ARCH@|$3|" -e "s|@MINIMUM_OS@|$4|" \
        packaging/control > "$root/DEBIAN/control"
    for script in postinst postrm; do
        sed -e "s|@SHELL@|$5|" -e "s|@PREFIX@|$2|g" "packaging/$script" > "$root/DEBIAN/$script"
        [ "$1" = roothide ] && roothide_path "$root/DEBIAN/$script"
        chmod 0755 "$root/DEBIAN/$script"
    done
    dpkg-deb -Zgzip --root-owner-group -b "$root" "build/com.rostane.share_${version}_$3.deb" >/dev/null
    echo "build/com.rostane.share_${version}_$3.deb"
}
package rootful "" iphoneos-arm 12.0 /bin/sh
package rootless /var/jb iphoneos-arm64 12.0 /var/jb/bin/sh
package roothide "" iphoneos-arm64e 15.0 /bin/sh
