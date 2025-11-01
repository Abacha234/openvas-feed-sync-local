# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840869");
  script_cve_id("CVE-2012-0029");
  script_tag(name:"creation_date", value:"2012-01-25 05:45:16 +0000 (Wed, 25 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1339-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the USN-1339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicolae Mogoreanu discovered that QEMU did not properly verify legacy mode
packets in the e1000 network driver. A remote attacker could exploit this
to cause a denial of service or possibly execute code with the privileges
of the user invoking the program.

When using QEMU with libvirt or virtualization management software based on
libvirt such as Eucalyptus and OpenStack, QEMU guests are individually
isolated by an AppArmor profile by default in Ubuntu.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
