# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842143");
  script_cve_id("CVE-2013-7421", "CVE-2014-7822", "CVE-2014-9644", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0274");
  script_tag(name:"creation_date", value:"2015-03-25 05:32:59 +0000 (Wed, 25 Mar 2015)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2544-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2544-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2544-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2544-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Windisch discovered flaw in how the Linux kernel's XFS file system
replaces remote attributes. A local access with access to an XFS file
system could exploit this flaw to escalate their privileges.
(CVE-2015-0274)

A flaw was discovered in the automatic loading of modules in the crypto
subsystem of the Linux kernel. A local user could exploit this flaw to load
installed kernel modules, increasing the attack surface and potentially
using this to gain administrative privileges. (CVE-2013-7421)

The Linux kernel's splice system call did not correctly validate its
parameters. A local, unprivileged user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-7822)

A flaw was discovered in the crypto subsystem when screening module names
for automatic module loading if the name contained a valid crypto module
name, eg. vfat(aes). A local user could exploit this flaw to load installed
kernel modules, increasing the attack surface and potentially using this to
gain administrative privileges. (CVE-2014-9644)

Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) failed to
verify symlink size info. A local attacker, who is able to mount a malicious
UDF file system image, could exploit this flaw to cause a denial of service
(system crash) or possibly cause other undesired behaviors. (CVE-2014-9728)

Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) did not
valid inode size information. A local attacker, who is able to mount a
malicious UDF file system image, could exploit this flaw to cause a denial
of service (system crash) or possibly cause other undesired behaviors.
(CVE-2014-9729)

Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) did not
correctly verify the component length for symlinks. A local attacker, who
is able to mount a malicious UDF file system image, could exploit this flaw
to cause a denial of service (system crash) or possibly cause other
undesired behaviors. (CVE-2014-9730)

Carl H Lunde discovered an information leak in the UDF file system
(CONFIG_UDF_FS). A local attacker, who is able to mount a malicious UDF file
system image, could exploit this flaw to read potential sensitive kernel
memory. (CVE-2014-9731)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
