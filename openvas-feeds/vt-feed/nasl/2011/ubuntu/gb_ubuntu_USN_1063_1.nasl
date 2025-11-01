# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840585");
  script_cve_id("CVE-2011-0011");
  script_tag(name:"creation_date", value:"2011-02-16 13:19:17 +0000 (Wed, 16 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1063-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1063-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1063-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the USN-1063-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Neil Wilson discovered that if VNC passwords were blank in QEMU
configurations, access to VNC sessions was allowed without a password
instead of being disabled. A remote attacker could connect to running
VNC sessions of QEMU and directly control the system. By default, QEMU
does not start VNC sessions.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
