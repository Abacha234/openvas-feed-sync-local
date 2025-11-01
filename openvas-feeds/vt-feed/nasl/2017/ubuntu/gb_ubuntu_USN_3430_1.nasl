# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843319");
  script_cve_id("CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_tag(name:"creation_date", value:"2017-10-05 06:24:50 +0000 (Thu, 05 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)");

  script_name("Ubuntu: Security Advisory (USN-3430-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3430-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3430-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the USN-3430-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled DNS requests. A remote attacker
could use this issue to cause Dnsmasq to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2017-14491)

Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled IPv6 router advertisements. A
remote attacker could use this issue to cause Dnsmasq to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2017-14492)

Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled DHCPv6 requests. A remote
attacker could use this issue to cause Dnsmasq to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2017-14493)

Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled DHCPv6 packets. A remote
attacker could use this issue to possibly obtain sensitive memory contents.
(CVE-2017-14494)

Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled DNS requests. A remote attacker
could use this issue to cause Dnsmasq to consume memory, resulting in a
denial of service. (CVE-2017-14495)

Felix Wilhelm, Fermin J. Serna, Gabriel Campana and Kevin Hamacher
discovered that Dnsmasq incorrectly handled DNS requests. A remote attacker
could use this issue to cause Dnsmasq to crash, resulting in a denial of
service. (CVE-2017-14496)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
