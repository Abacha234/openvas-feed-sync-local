# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841250");
  script_cve_id("CVE-2012-4444");
  script_tag(name:"creation_date", value:"2012-12-14 04:21:55 +0000 (Fri, 14 Dec 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1664-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1664-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhang Zuotao discovered a bug in the Linux kernel's handling of overlapping
fragments in ipv6. A remote attacker could exploit this flaw to bypass
firewalls and initial new network connections that should have been blocked
by the firewall.");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
