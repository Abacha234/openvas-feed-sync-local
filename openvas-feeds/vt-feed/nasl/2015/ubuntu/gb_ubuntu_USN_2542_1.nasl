# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842146");
  script_cve_id("CVE-2014-7822", "CVE-2014-9419", "CVE-2014-9683", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1421");
  script_tag(name:"creation_date", value:"2015-03-25 05:33:39 +0000 (Wed, 25 Mar 2015)");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2542-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2542-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-2542-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Linux kernel's splice system call did not correctly validate its
parameters. A local, unprivileged user could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-7822)

A flaw was discovered in how Thread Local Storage (TLS) is handled by the
task switching function in the Linux kernel for x86_64 based machines. A
local user could exploit this flaw to bypass the Address Space Layout
Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted file
name decoding. A local unprivileged user could exploit this flaw to cause a
denial of service (system crash) or potentially gain administrative
privileges. (CVE-2014-9683)

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
memory. (CVE-2014-9731)

Sun Baoliang discovered a use after free flaw in the Linux kernel's SCTP
(Stream Control Transmission Protocol) subsystem during INIT collisions. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) or potentially escalate their privileges on the system.
(CVE-2015-1421)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
