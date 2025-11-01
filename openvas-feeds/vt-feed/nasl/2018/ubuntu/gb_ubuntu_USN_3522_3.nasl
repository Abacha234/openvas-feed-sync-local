# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843414");
  script_cve_id("CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-11 06:38:35 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3522-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3522-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3522-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1741934");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3522-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3522-1 fixed a vulnerability in the Linux kernel to address
Meltdown (CVE-2017-5754). Unfortunately, that update introduced
a regression where a few systems failed to boot successfully. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Jann Horn discovered that microprocessors utilizing speculative execution
 and indirect branch prediction may allow unauthorized memory reads via
 sidechannel attacks. This flaw is known as Meltdown. A local attacker could
 use this to expose sensitive information, including kernel memory.");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
