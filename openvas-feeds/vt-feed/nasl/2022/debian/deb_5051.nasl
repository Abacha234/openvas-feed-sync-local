# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705051");
  script_cve_id("CVE-2021-45417");
  script_tag(name:"creation_date", value:"2022-01-22 02:00:13 +0000 (Sat, 22 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-26 19:49:00 +0000 (Wed, 26 Jan 2022)");

  script_name("Debian: Security Advisory (DSA-5051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5051");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5051");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/aide");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'aide' package(s) announced via the DSA-5051 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman discovered a heap-based buffer overflow vulnerability in the base64 functions of aide, an advanced intrusion detection system, which can be triggered via large extended file attributes or ACLs. This may result in denial of service or privilege escalation.

For the oldstable distribution (buster), this problem has been fixed in version 0.16.1-1+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 0.17.3-4+deb11u1.

We recommend that you upgrade your aide packages.

For the detailed security status of aide please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'aide' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);