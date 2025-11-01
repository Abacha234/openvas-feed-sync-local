# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840969");
  script_cve_id("CVE-2011-4127", "CVE-2012-2100");
  script_tag(name:"creation_date", value:"2012-03-29 04:35:34 +0000 (Thu, 29 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1405-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1405-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paolo Bonzini discovered a flaw in Linux's handling of the SG_IO ioctl
command. A local user, or user in a VM could exploit this flaw to bypass
restrictions and gain read/write access to all data on the affected block
device. (CVE-2011-4127)

A flaw was found in the Linux kernel's ext4 file system when mounting a
corrupt filesystem. A user-assisted remote attacker could exploit this flaw
to cause a denial of service. (CVE-2012-2100)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
