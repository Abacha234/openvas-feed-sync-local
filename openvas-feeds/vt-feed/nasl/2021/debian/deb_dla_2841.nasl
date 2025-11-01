# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892841");
  script_cve_id("CVE-2021-43784");
  script_tag(name:"creation_date", value:"2021-12-07 02:00:21 +0000 (Tue, 07 Dec 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-08 18:05:00 +0000 (Wed, 08 Dec 2021)");

  script_name("Debian: Security Advisory (DLA-2841)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2841");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2841");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'runc' package(s) announced via the DLA-2841 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an overflow issue in runc, the runtime for the Open Container Project, often used with Docker.

The Netlink 'bytemsg' length field could have allowed an attacker to override Netlink-based container configurations. This vulnerability required the attacker to have some control over the configuration of the container, but would have allowed the attacker to bypass the namespace restrictions of the container by simply adding their own Netlink payload which disables all namespaces.

CVE-2021-43784

For Debian 9 Stretch, these problems have been fixed in version 0.1.1+dfsg1-2+deb9u3.

We recommend that you upgrade your runc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'runc' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);