# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03467.1");
  script_cve_id("CVE-2023-40175", "CVE-2024-21647", "CVE-2024-45614");
  script_tag(name:"creation_date", value:"2025-10-09 04:06:46 +0000 (Thu, 09 Oct 2025)");
  script_version("2025-10-09T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-24 18:48:29 +0000 (Thu, 24 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03467-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03467-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503467-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230848");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042012.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-puma' package(s) announced via the SUSE-SU-2025:03467-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-puma fixes the following issues:

Update to version 5.6.9.

- CVE-2024-45614: improper header normalization allows for clients to clobber proxy set headers, which can lead to
 information leaks (bsc#1230848, fixed in an earlier update).
- CVE-2024-21647: unbounded resource consumption due to invalid parsing of chunked encoding in HTTP/1.1 can lead to
 denial-of-service attacks (bsc#1218638, fixed in an earlier update)
- CVE-2023-40175: incorrect behavior when parsing chunked transfer encoding bodies and zero-length Content-Length
 headers can lead to HTTP request smuggling attacks (bsc#1214425, fixed in an earlier update).");

  script_tag(name:"affected", value:"'rubygem-puma' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma", rpm:"ruby2.5-rubygem-puma~5.6.9~150600.18.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-puma-doc", rpm:"ruby2.5-rubygem-puma-doc~5.6.9~150600.18.3.1", rls:"openSUSELeap15.6"))) {
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
