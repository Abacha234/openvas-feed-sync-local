# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842220");
  script_cve_id("CVE-2015-1779", "CVE-2015-2756", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2015-06-09 09:08:26 +0000 (Tue, 09 Jun 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 11:40:00 +0000 (Mon, 05 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-2608-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2608-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2608-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2608-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jason Geffner discovered that QEMU incorrectly handled the virtual floppy
driver. This issue is known as VENOM. A malicious guest could use this
issue to cause a denial of service, or possibly execute arbitrary code on
the host as the user running the QEMU process. In the default installation,
when QEMU is used with libvirt, attackers would be isolated by the libvirt
AppArmor profile. (CVE-2015-3456)

Daniel P. Berrange discovered that QEMU incorrectly handled VNC websockets.
A remote attacker could use this issue to cause QEMU to consume memory,
resulting in a denial of service. This issue only affected Ubuntu 14.04
LTS, Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-1779)

Jan Beulich discovered that QEMU, when used with Xen, didn't properly
restrict access to PCI command registers. A malicious guest could use this
issue to cause a denial of service. This issue only affected Ubuntu 14.04
LTS and Ubuntu 14.10. (CVE-2015-2756)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
