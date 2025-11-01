# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892503");
  script_cve_id("CVE-2020-7788");
  script_tag(name:"creation_date", value:"2020-12-22 04:00:10 +0000 (Tue, 22 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-02 19:40:00 +0000 (Fri, 02 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-2503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2503");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2503");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-ini' package(s) announced via the DLA-2503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in node-ini, a .ini format parser and serializer for Node.js, where an application could be exploited by a malicious input file.

CVE-2020-7788

This affects the package ini before 1.3.6. If an attacker submits a malicious INI file to an application that parses it with ini.parse, they will pollute the prototype on the application. This can be exploited further depending on the context.

For Debian 9 Stretch, these problems have been fixed in version 1.1.0-1+deb9u1.

We recommend that you upgrade your node-ini packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-ini' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);