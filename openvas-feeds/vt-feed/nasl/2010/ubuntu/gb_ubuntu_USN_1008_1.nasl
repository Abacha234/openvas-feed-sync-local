# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840522");
  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1008-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1008-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-1008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvirt would probe disk backing stores without
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

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
