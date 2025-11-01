# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844222");
  script_cve_id("CVE-2019-11481", "CVE-2019-11482", "CVE-2019-11483", "CVE-2019-11485", "CVE-2019-15790");
  script_tag(name:"creation_date", value:"2019-11-06 03:01:19 +0000 (Wed, 06 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4171-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4171-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4171-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1850929");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-4171-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4171-1 fixed vulnerabilities in Apport. The update caused a regression
in the Python Apport library. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Kevin Backhouse discovered Apport would read its user-controlled settings
 file as the root user. This could be used by a local attacker to possibly
 crash Apport or have other unspecified consequences. (CVE-2019-11481)

 Sander Bos discovered a race-condition in Apport during core dump
 creation. This could be used by a local attacker to generate a crash report
 for a privileged process that is readable by an unprivileged user.
 (CVE-2019-11482)

 Sander Bos discovered Apport mishandled crash dumps originating from
 containers. This could be used by a local attacker to generate a crash
 report for a privileged process that is readable by an unprivileged user.
 (CVE-2019-11483)

 Sander Bos discovered Apport mishandled lock-file creation. This could be
 used by a local attacker to cause a denial of service against Apport.
 (CVE-2019-11485)

 Kevin Backhouse discovered Apport read various process-specific files with
 elevated privileges during crash dump generation. This could could be used
 by a local attacker to generate a crash report for a privileged process
 that is readable by an unprivileged user. (CVE-2019-15790)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
