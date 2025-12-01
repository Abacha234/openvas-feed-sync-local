# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.97359710010098102998");
  script_cve_id("CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572", "CVE-2023-27530", "CVE-2023-27539", "CVE-2024-25126", "CVE-2024-26141", "CVE-2024-26146", "CVE-2025-25184", "CVE-2025-27111", "CVE-2025-27610", "CVE-2025-32441", "CVE-2025-46727", "CVE-2025-59830", "CVE-2025-61770", "CVE-2025-61771", "CVE-2025-61772", "CVE-2025-61780", "CVE-2025-61919");
  script_tag(name:"creation_date", value:"2025-11-13 04:08:28 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 19:44:47 +0000 (Tue, 17 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a35addbf9b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a35addbf9b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a35addbf9b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164714");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164719");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179649");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265593");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265594");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265596");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265598");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2345301");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2345712");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349810");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349978");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351231");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351278");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364965");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364999");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2365052");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398167");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402175");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402200");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402987");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403180");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403529");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rack' package(s) announced via the FEDORA-2025-a35addbf9b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to Rack 2.2.21");

  script_tag(name:"affected", value:"'rubygem-rack' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack", rpm:"rubygem-rack~2.2.21~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-doc", rpm:"rubygem-rack-doc~2.2.21~1.fc41", rls:"FC41"))) {
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
