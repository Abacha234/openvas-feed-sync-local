# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844556");
  script_cve_id("CVE-2020-15861", "CVE-2020-15862");
  script_tag(name:"creation_date", value:"2020-09-02 06:22:16 +0000 (Wed, 02 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4471-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4471-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4471-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1892980");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the USN-4471-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4471-1 fixed a vulnerability in Net-SNMP. The updated introduced a regression making
nsExtendCacheTime not settable. This update fixes the problem adding the cacheTime feature flag.

Original advisory details:

 Tobias Neitzel discovered that Net-SNMP incorrectly handled certain symlinks.
 An attacker could possibly use this issue to access sensitive information.
 (CVE-2020-15861)

 It was discovered that Net-SNMP incorrectly handled certain inputs.
 An attacker could possibly use this issue to execute arbitrary code.
 This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu
 18.04 LTS, and Ubuntu 20.04 LTS. (CVE-2020-15862)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
