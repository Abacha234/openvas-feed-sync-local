# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892610");
  script_cve_id("CVE-2020-27170", "CVE-2020-27171", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28660", "CVE-2021-3348", "CVE-2021-3428");
  script_tag(name:"creation_date", value:"2021-03-31 03:00:27 +0000 (Wed, 31 Mar 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-12 03:54:00 +0000 (Mon, 12 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-2610)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2610");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2610");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-4.19");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.19' package(s) announced via the DLA-2610 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-26930 CVE-2021-26931 CVE-2021-26932 CVE-2021-27363 CVE-2021-27364 CVE-2021-27365 CVE-2021-28038 CVE-2021-28660 Debian Bug : 983595

Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service, or information leaks.

CVE-2020-27170

, CVE-2020-27171

Piotr Krysiuk discovered flaws in the BPF subsystem's checks for information leaks through speculative execution. A local user could use these to obtain sensitive information from kernel memory.

CVE-2021-3348

ADlab of venustech discovered a race condition in the nbd block driver that can lead to a use-after-free. A local user with access to an nbd block device could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2021-3428

Wolfgang Frisch reported a potential integer overflow in the ext4 filesystem driver. A user permitted to mount arbitrary filesystem images could use this to cause a denial of service (crash).

CVE-2021-26930

(XSA-365)

Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H. Schonherr discovered that the Xen block backend driver (xen-blkback) did not handle grant mapping errors correctly. A malicious guest could exploit this bug to cause a denial of service (crash), or possibly an information leak or privilege escalation, within the domain running the backend, which is typically dom0.

CVE-2021-26931

(XSA-362), CVE-2021-26932 (XSA-361), CVE-2021-28038 (XSA-367)

Jan Beulich discovered that the Xen support code and various Xen backend drivers did not handle grant mapping errors correctly. A malicious guest could exploit these bugs to cause a denial of service (crash) within the domain running the backend, which is typically dom0.

CVE-2021-27363

Adam Nichols reported that the iSCSI initiator subsystem did not properly restrict access to transport handle attributes in sysfs. On a system acting as an iSCSI initiator, this is an information leak to local users and makes it easier to exploit CVE-2021-27364.

CVE-2021-27364

Adam Nichols reported that the iSCSI initiator subsystem did not properly restrict access to its netlink management interface. On a system acting as an iSCSI initiator, a local user could use these to cause a denial of service (disconnection of storage) or possibly for privilege escalation.

CVE-2021-27365

Adam Nichols reported that the iSCSI initiator subsystem did not correctly limit the lengths of parameters or passthrough PDUs sent through its netlink management interface. On a system acting as an iSCSI initiator, a local user could use these to leak the contents of kernel memory, to cause a denial of service (kernel memory corruption or crash), and probably for privilege escalation.

CVE-2021-28660

It was discovered that the rtl8188eu WiFi driver did not correctly limit the length of SSIDs copied into scan ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.19' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);