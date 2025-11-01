# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703977");
  script_cve_id("CVE-2017-14500");
  script_tag(name:"creation_date", value:"2017-09-17 22:00:00 +0000 (Sun, 17 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-21 20:15:00 +0000 (Wed, 21 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-3977)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3977");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3977");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'newsbeuter' package(s) announced via the DSA-3977 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that podbeuter, the podcast fetcher in newsbeuter, a text-mode RSS feed reader, did not properly escape the name of the media enclosure (the podcast file), allowing a remote attacker to run an arbitrary shell command on the client machine. This is only exploitable if the file is also played in podbeuter.

For the oldstable distribution (jessie), this problem has been fixed in version 2.8-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed in version 2.9-5+deb9u2.

For the unstable distribution (sid), this problem has been fixed in version 2.9-7.

We recommend that you upgrade your newsbeuter packages.");

  script_tag(name:"affected", value:"'newsbeuter' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);