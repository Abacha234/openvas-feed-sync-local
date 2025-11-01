# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892931");
  script_cve_id("CVE-2022-24407");
  script_tag(name:"creation_date", value:"2022-03-07 02:00:09 +0000 (Mon, 07 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 19:08:00 +0000 (Thu, 03 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2931)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2931");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2931");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cyrus-sasl2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl2' package(s) announced via the DLA-2931 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SQL plugin in cyrus-sasl2, a library implementing the Simple Authentication and Security Layer, is prone to a SQL injection attack. An authenticated remote attacker can take advantage of this flaw to execute arbitrary SQL commands and for privilege escalation.

For Debian 9 stretch, this problem has been fixed in version 2.1.27~101-g0780600+dfsg-3+deb9u2.

We recommend that you upgrade your cyrus-sasl2 packages.

For the detailed security status of cyrus-sasl2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cyrus-sasl2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);