# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841892");
  script_cve_id("CVE-2014-3917", "CVE-2014-4943");
  script_tag(name:"creation_date", value:"2014-07-21 10:55:09 +0000 (Mon, 21 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2282-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2282-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2282-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2282-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sasha Levin reported a flaw in the Linux kernel's point-to-point protocol
(PPP) when used with the Layer Two Tunneling Protocol (L2TP). A local user
could exploit this flaw to gain administrative privileges. (CVE-2014-4943)

An flaw was discovered in the Linux kernel's audit subsystem when auditing
certain syscalls. A local attacker could exploit this flaw to obtain
potentially sensitive single-bit values from kernel memory or cause a
denial of service (OOPS). (CVE-2014-3917)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
