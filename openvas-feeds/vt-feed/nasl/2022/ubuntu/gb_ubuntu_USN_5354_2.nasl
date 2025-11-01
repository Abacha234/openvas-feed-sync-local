# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845356");
  script_cve_id("CVE-2022-21716");
  script_tag(name:"creation_date", value:"2022-05-06 01:00:43 +0000 (Fri, 06 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 17:45:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5354-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5354-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5354-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'twisted' package(s) announced via the USN-5354-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5354-1 fixed vulnerabilities in Twisted. This update provides the
corresponding updates for Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and
Ubuntu 22.04 LTS.

Original advisory details:

 It was discovered that Twisted incorrectly processed SSH handshake data on
 connection establishments. A remote attacker could use this issue to cause
 Twisted to crash, resulting in a denial of service. (CVE-2022-21716)");

  script_tag(name:"affected", value:"'twisted' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
