# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845396");
  script_cve_id("CVE-2020-14342", "CVE-2021-20208", "CVE-2022-27239", "CVE-2022-29869");
  script_tag(name:"creation_date", value:"2022-06-03 01:00:31 +0000 (Fri, 03 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 18:49:00 +0000 (Fri, 06 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5459-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5459-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils' package(s) announced via the USN-5459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aurelien Aptel discovered that cifs-utils invoked a shell when requesting a
password. In certain environments, a local attacker could possibly use this
issue to escalate privileges. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-14342)

It was discovered that cifs-utils incorrectly used host credentials when
mounting a krb5 CIFS file system from within a container. An attacker
inside a container could possibly use this issue to obtain access to
sensitive information. This issue only affected Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2021-20208)

It was discovered that cifs-utils incorrectly handled certain command-line
arguments. A local attacker could possibly use this issue to obtain root
privileges. (CVE-2022-27239)

It was discovered that cifs-utils incorrectly handled verbose logging. A
local attacker could possibly use this issue to obtain sensitive
information. (CVE-2022-29869)");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
