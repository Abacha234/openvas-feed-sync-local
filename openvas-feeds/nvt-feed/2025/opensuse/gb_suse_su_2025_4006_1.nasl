# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4006.1");
  script_cve_id("CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11713", "CVE-2025-11714", "CVE-2025-11715");
  script_tag(name:"creation_date", value:"2025-11-12 15:17:42 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4006-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254006-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1952100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1973699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1975147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1979323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1979536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1983838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1986142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1986845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1987624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1987880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1988244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1988912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1988931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1989978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1990085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1990970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1991040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1991899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1992027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1992113");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023193.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:4006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MFSA 2025-85 (bsc#1251263):

 * CVE-2025-11708 (bmo#1988931)
 Use-after-free in MediaTrackGraphImpl::GetInstance()
 * CVE-2025-11709 (bmo#1989127)
 Out of bounds read/write in a privileged process triggered by
 WebGL textures
 * CVE-2025-11710 (bmo#1989899)
 Cross-process information leaked due to malicious IPC
 messages
 * CVE-2025-11711 (bmo#1989978)
 Some non-writable Object properties could be modified
 * CVE-2025-11712 (bmo#1979536)
 An OBJECT tag type attribute overrode browser behavior on web
 resources without a content-type
 * CVE-2025-11713 (bmo#1986142)
 Potential user-assisted code execution in 'Copy as cURL'
 command
 * CVE-2025-11714 (bmo#1973699, bmo#1989945, bmo#1990970,
 bmo#1991040, bmo#1992113)
 Memory safety bugs fixed in Firefox ESR 115.29, Firefox ESR
 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144
 * CVE-2025-11715 (bmo#1983838, bmo#1987624, bmo#1988244,
 bmo#1988912, bmo#1989734, bmo#1990085, bmo#1991899)
 Memory safety bugs fixed in Firefox ESR 140.4, Thunderbird
 ESR 140.4, Firefox 144 and Thunderbird 144");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~140.4.0~150200.8.242.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~140.4.0~150200.8.242.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~140.4.0~150200.8.242.1", rls:"openSUSELeap15.6"))) {
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
