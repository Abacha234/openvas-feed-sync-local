# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4489.1");
  script_cve_id("CVE-2025-67735");
  script_tag(name:"creation_date", value:"2025-12-22 04:22:11 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4489-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4489-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254489-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255048");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023632.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty' package(s) announced via the SUSE-SU-2025:4489-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty fixes the following issues:

Update to upstream version 4.1.130.

Security issues fixed:

- CVE-2025-67735: lack of URI sanitization in `HttpRequestEncoder` allows for CRLF injection through a request URI and
 can lead to request smuggling (bsc#1255048).

Other updates and bugfixes:

- Version 4.1.130:
 * Update `lz4-java` version to 1.10.1
 * Close `Channel` and fail bootstrap when setting a `ChannelOption` causes an error
 * Discard the following `HttpContent` for preflight request
 * Fix race condition in `NonStickyEventExecutorGroup` causing incorrect `inEventLoop()` results
 * Fix Zstd compression for large data
 * Fix `ZstdEncoder` not producing data when source is smaller than block
 * Make big endian ASCII hashcode consistent with little endian
 * Fix reentrancy bug in `ByteToMessageDecoder`
 * Add 32k and 64k size classes to adaptive allocator
 * Re-enable reflective field accesses in native images
 * Correct HTTP/2 padding length check
 * Fix HTTP startline validation
 * Fix `MpscIntQueue` bug

- Build against the `org.jboss:jdk-misc` artifact that is implementing the `sun.misc` classes removed in Java 25");

  script_tag(name:"affected", value:"'netty' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.130~150200.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.130~150200.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
