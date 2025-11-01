# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842661");
  script_cve_id("CVE-2015-3146", "CVE-2016-0739");
  script_tag(name:"creation_date", value:"2016-02-24 05:25:31 +0000 (Wed, 24 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-20 15:07:00 +0000 (Wed, 20 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2912-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2912-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the USN-2912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mariusz Ziulek discovered that libssh incorrectly handled certain packets.
A remote attacker could possibly use this issue to cause libssh to crash,
resulting in a denial of service.
(CVE-2015-3146)

Aris Adamantiadis discovered that libssh incorrectly generated ephemeral
secret keys of 128 bits instead of the recommended 1024 or 2048 bits when
using the diffie-hellman-group1 and diffie-hellman-group14 methods. If a
remote attacker were able to perform a machine-in-the-middle attack, this flaw
could be exploited to view sensitive information. (CVE-2016-0739)");

  script_tag(name:"affected", value:"'libssh' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
