# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842081");
  script_cve_id("CVE-2014-8133", "CVE-2014-9420");
  script_tag(name:"creation_date", value:"2015-02-04 05:10:41 +0000 (Wed, 04 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2490-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2490-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2490-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2490-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Lutomirski discovered an information leak in the Linux kernel's Thread
Local Storage (TLS) implementation allowing users to bypass the espfix to
obtain information that could be used to bypass the Address Space Layout
Randomization (ASLR) protection mechanism. A local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-8133)

Prasad J Pandit reported a flaw in the rock_continue function of the Linux
kernel's ISO 9660 CDROM file system. A local user could exploit this flaw
to cause a denial of service (system crash or hang). (CVE-2014-9420)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
