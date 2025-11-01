# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841084");
  script_cve_id("CVE-2012-1601", "CVE-2012-2744");
  script_tag(name:"creation_date", value:"2012-07-19 05:14:14 +0000 (Thu, 19 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1507-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1507-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
cpu setup. An unprivileged local user could exploit this flaw to crash the
system leading to a denial of service. (CVE-2012-1601)

An error was found in the Linux kernel's IPv6 netfilter when connection
tracking is enabled. A remote attacker could exploit this flaw to crash a
system if it is using IPv6 with the nf_contrack_ipv6 kernel module loaded.
(CVE-2012-2744)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
