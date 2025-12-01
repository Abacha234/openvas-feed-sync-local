# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99555991014089");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58058", "CVE-2025-8556", "CVE-2025-8959");
  script_tag(name:"creation_date", value:"2025-11-17 04:10:17 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-06 09:15:28 +0000 (Wed, 06 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-c555ce4089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c555ce4089");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c555ce4089");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375615");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384150");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2386297");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388884");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2390857");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2391634");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398604");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399268");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opentofu' package(s) announced via the FEDORA-2025-c555ce4089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.10.7");

  script_tag(name:"affected", value:"'opentofu' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"opentofu", rpm:"opentofu~1.10.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opentofu-debuginfo", rpm:"opentofu-debuginfo~1.10.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opentofu-debugsource", rpm:"opentofu-debugsource~1.10.7~1.fc41", rls:"FC41"))) {
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
