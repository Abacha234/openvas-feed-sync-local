# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840256");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-670-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-670-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-670-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/+bug/296841");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadow, vm-builder' package(s) announced via the USN-670-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Gug discovered that vm-builder improperly set the root
password when creating virtual machines. An attacker could exploit
this to gain root privileges to the virtual machine by using a
predictable password.

This vulnerability only affects virtual machines created with
vm-builder under Ubuntu 8.10, and does not affect native Ubuntu
installations. An update was made to the shadow package to detect
vulnerable systems and disable password authentication for the
root account. Vulnerable virtual machines which an attacker has
access to should be considered compromised, and appropriate actions
taken to secure the machine.");

  script_tag(name:"affected", value:"'shadow, vm-builder' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
