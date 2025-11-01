# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841869");
  script_cve_id("CVE-2013-6433", "CVE-2014-0187", "CVE-2014-4167");
  script_tag(name:"creation_date", value:"2014-07-01 16:05:34 +0000 (Tue, 01 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2255-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2255-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2255-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'neutron' package(s) announced via the USN-2255-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Darragh O'Reilly discovered that the Ubuntu packaging for OpenStack Neutron
did not properly set up its sudo configuration. If a different flaw was
found in OpenStack Neutron, this vulnerability could be used to escalate
privileges. (CVE-2013-6433)

Stephen Ma and Christoph Thiel discovered that the openvswitch-agent in
OpenStack Neutron did not properly perform input validation when creating
security group rules when specifying --remote-ip-prefix. A remote
authenticated attacker could exploit this to prevent application of
additional rules. (CVE-2014-0187)

Thiago Martins discovered that OpenStack Neutron would inappropriately
apply SNAT rules to IPv6 subnets when using the L3-agent. A remote
authenticated attacker could exploit this to prevent floating IPv4
addresses from being attached throughout the cloud. (CVE-2014-4167)");

  script_tag(name:"affected", value:"'neutron' package(s) on Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
