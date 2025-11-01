# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892601");
  script_cve_id("CVE-2021-3429");
  script_tag(name:"creation_date", value:"2021-03-20 04:00:10 +0000 (Sat, 20 Mar 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-2601)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2601");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2601");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cloud-init");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cloud-init' package(s) announced via the DLA-2601 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cloud-init has the ability to generate and set a randomized password for system users. This functionality is enabled at runtime by passing cloud-config data such as:

chpasswd: list: <pipe> user1:RANDOM

When used this way, cloud-init logs the raw, unhashed password to a world-readable local file.

For Debian 9 stretch, this problem has been fixed in version 0.7.9-2+deb9u1.

We recommend that you upgrade your cloud-init packages.

For the detailed security status of cloud-init please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'cloud-init' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);