# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704227");
  script_cve_id("CVE-2018-1002200");
  script_tag(name:"creation_date", value:"2018-06-11 22:00:00 +0000 (Mon, 11 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:32:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4227");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4227");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/plexus-archiver");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'plexus-archiver' package(s) announced via the DSA-4227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Danny Grander discovered a directory traversal flaw in plexus-archiver, an Archiver plugin for the Plexus compiler system, allowing an attacker to overwrite any file writable by the extracting user via a specially crafted Zip archive.

For the oldstable distribution (jessie), this problem has been fixed in version 1.2-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 2.2-1+deb9u1.

We recommend that you upgrade your plexus-archiver packages.

For the detailed security status of plexus-archiver please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'plexus-archiver' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);