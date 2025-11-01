# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705059");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-4034");
  script_tag(name:"creation_date", value:"2022-01-26 02:00:15 +0000 (Wed, 26 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 17:50:00 +0000 (Mon, 31 Jan 2022)");

  script_name("Debian: Security Advisory (DSA-5059)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5059");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5059");
  script_xref(name:"URL", value:"https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/policykit-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'policykit-1' package(s) announced via the DSA-5059 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs discovered a local privilege escalation in PolicyKit's pkexec.

Details can be found in the Qualys advisory at [link moved to references]

For the oldstable distribution (buster), this problem has been fixed in version 0.105-25+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in version 0.105-31+deb11u1.

We recommend that you upgrade your policykit-1 packages.

For the detailed security status of policykit-1 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'policykit-1' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);