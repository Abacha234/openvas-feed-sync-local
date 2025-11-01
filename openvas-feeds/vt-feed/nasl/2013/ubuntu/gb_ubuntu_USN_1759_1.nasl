# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841361");
  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2275");
  script_tag(name:"creation_date", value:"2013-03-15 04:36:08 +0000 (Fri, 15 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1759-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1759-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1759-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the USN-1759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Puppet agents incorrectly handled certain kick
connections in a non-default configuration. An attacker on an authenticated
client could use this issue to possibly execute arbitrary code.
(CVE-2013-1653)

It was discovered that Puppet incorrectly handled certain catalog requests.
An attacker on an authenticated client could use this issue to possibly
execute arbitrary code on the master. (CVE-2013-1640)

It was discovered that Puppet incorrectly handled certain client requests.
An attacker on an authenticated client could use this issue to possibly
perform unauthorized actions. (CVE-2013-1652)

It was discovered that Puppet incorrectly handled certain SSL connections.
An attacker could use this issue to possibly downgrade connections to
SSLv2. (CVE-2013-1654)

It was discovered that Puppet incorrectly handled serialized attributes.
An attacker on an authenticated client could use this issue to possibly
cause a denial of service, or execute arbitrary. (CVE-2013-1655)

It was discovered that Puppet incorrectly handled submitted reports.
An attacker on an authenticated node could use this issue to possibly
submit a report for any other node. (CVE-2013-2275)");

  script_tag(name:"affected", value:"'puppet' package(s) on Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
