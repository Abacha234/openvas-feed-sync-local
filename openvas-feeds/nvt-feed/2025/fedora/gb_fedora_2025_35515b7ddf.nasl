# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.35515987100100102");
  script_cve_id("CVE-2025-22868", "CVE-2025-22869", "CVE-2025-22870", "CVE-2025-22872", "CVE-2025-30204");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-35515b7ddf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-35515b7ddf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-35515b7ddf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254045");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336979");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337234");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2341265");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348838");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350844");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352327");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354433");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360615");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360653");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rclone' package(s) announced via the FEDORA-2025-35515b7ddf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for rclone-1.70.2-1.fc43.

##### **Changelog**

```
* Sun Jul 6 2025 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 1.70.2-1
- Update to 1.70.2 - Closes rhbz#2254045 rhbz#2336979 rhbz#2337234
 rhbz#2341265 rhbz#2348838 rhbz#2350844 rhbz#2352327 rhbz#2354433
 rhbz#2360615 rhbz#2360653

```");

  script_tag(name:"affected", value:"'rclone' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"rclone", rpm:"rclone~1.70.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rclone-debuginfo", rpm:"rclone-debuginfo~1.70.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rclone-debugsource", rpm:"rclone-debugsource~1.70.2~1.fc43", rls:"FC43"))) {
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
