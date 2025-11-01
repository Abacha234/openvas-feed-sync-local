# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893292");
  script_cve_id("CVE-2023-22741");
  script_tag(name:"creation_date", value:"2023-01-30 09:59:06 +0000 (Mon, 30 Jan 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 12:54:00 +0000 (Fri, 27 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3292");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3292");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sofia-sip");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sofia-sip' package(s) announced via the DLA-3292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Missing message length and attributes length checks when handling STUN packages have been fixed in sofia-sip, a SIP (Session Initiation Protocol) User-Agent library.

For Debian 10 buster, this problem has been fixed in version 1.12.11+20110422.1-2.1+deb10u2.

We recommend that you upgrade your sofia-sip packages.

For the detailed security status of sofia-sip please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sofia-sip' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);