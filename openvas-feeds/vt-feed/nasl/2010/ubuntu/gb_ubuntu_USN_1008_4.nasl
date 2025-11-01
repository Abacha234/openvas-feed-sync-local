# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840534");
  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_tag(name:"creation_date", value:"2010-11-16 13:49:48 +0000 (Tue, 16 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1008-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1008-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1008-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/665531");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-1008-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1008-1 fixed vulnerabilities in libvirt. The upstream fixes for
CVE-2010-2238 changed the behavior of libvirt such that the domain
XML could not specify 'host_device' as the qemu sub-type. While libvirt
0.8.3 and later will longer support specifying this sub-type, this
update restores the old behavior on Ubuntu 10.04 LTS.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that libvirt would probe disk backing stores without
 consulting the defined format for the disk. A privileged attacker in the
 guest could exploit this to read arbitrary files on the host. This issue
 only affected Ubuntu 10.04 LTS. By default, guests are confined by an
 AppArmor profile which provided partial protection against this flaw.
 (CVE-2010-2237, CVE-2010-2238)

 It was discovered that libvirt would create new VMs without setting a
 backing store format. A privileged attacker in the guest could exploit this
 to read arbitrary files on the host. This issue did not affect Ubuntu 8.04
 LTS. In Ubuntu 9.10 and later guests are confined by an AppArmor profile
 which provided partial protection against this flaw. (CVE-2010-2239)

 Jeremy Nickurak discovered that libvirt created iptables rules with too
 lenient mappings of source ports. A privileged attacker in the guest could
 bypass intended restrictions to access privileged resources on the host.
 (CVE-2010-2242)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
