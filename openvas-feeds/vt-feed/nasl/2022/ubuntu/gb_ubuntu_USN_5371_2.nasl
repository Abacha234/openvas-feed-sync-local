# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845346");
  script_cve_id("CVE-2020-11724", "CVE-2020-36309", "CVE-2021-3618");
  script_tag(name:"creation_date", value:"2022-04-29 01:00:49 +0000 (Fri, 29 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 20:46:00 +0000 (Mon, 04 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5371-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5371-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5371-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the USN-5371-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5371-1 fixed several vulnerabilities in nginx.
This update provides the fix for CVE-2021-3618 for Ubuntu 22.04 LTS.

Original advisory details:

 It was discovered that nginx Lua module mishandled certain inputs.
 An attacker could possibly use this issue to perform an HTTP Request
 Smuggling attack. This issue only affects Ubuntu 18.04 LTS and
 Ubuntu 20.04 LTS. (CVE-2020-11724)

 It was discovered that nginx Lua module mishandled certain inputs.
 An attacker could possibly use this issue to disclose sensitive
 information. This issue only affects Ubuntu 18.04 LTS and
 Ubuntu 20.04 LTS. (CVE-2020-36309)

 It was discovered that nginx mishandled the use of
 compatible certificates among multiple encryption protocols.
 If a remote attacker were able to intercept the communication,
 this issue could be used to redirect traffic between subdomains.
 (CVE-2021-3618)");

  script_tag(name:"affected", value:"'nginx' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
