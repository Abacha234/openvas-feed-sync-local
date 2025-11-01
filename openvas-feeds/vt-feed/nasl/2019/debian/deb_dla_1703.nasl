# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891703");
  script_cve_id("CVE-2018-11307", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-14720", "CVE-2018-14721", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362");
  script_tag(name:"creation_date", value:"2019-03-03 23:00:00 +0000 (Sun, 03 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 14:15:00 +0000 (Mon, 31 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1703)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1703");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1703");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jackson-databind' package(s) announced via the DLA-1703 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several deserialization flaws were discovered in jackson-databind, a fast and powerful JSON library for Java, which could allow an unauthenticated user to perform code execution. The issue was resolved by extending the blacklist and blocking more classes from polymorphic deserialization.

For Debian 8 Jessie, these problems have been fixed in version 2.4.2-2+deb8u5.

We recommend that you upgrade your jackson-databind packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jackson-databind' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);