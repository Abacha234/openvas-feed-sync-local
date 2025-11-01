# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704763");
  script_cve_id("CVE-2020-12066");
  script_tag(name:"creation_date", value:"2020-09-16 03:00:04 +0000 (Wed, 16 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-01 00:15:00 +0000 (Thu, 01 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4763)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4763");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4763");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/teeworlds");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'teeworlds' package(s) announced via the DSA-4763 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that insufficient sanitising of received network packets in the game server of Teeworlds, an online multi-player platform 2D shooter, could result in denial of service.

For the stable distribution (buster), this problem has been fixed in version 0.7.2-5+deb10u1.

We recommend that you upgrade your teeworlds packages.

For the detailed security status of teeworlds please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'teeworlds' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);