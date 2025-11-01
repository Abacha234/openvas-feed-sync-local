# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892300");
  script_cve_id("CVE-2020-15954");
  script_tag(name:"creation_date", value:"2020-07-31 03:00:12 +0000 (Fri, 31 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:24:00 +0000 (Thu, 30 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2300)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2300");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2300");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdepim-runtime' package(s) announced via the DLA-2300 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue where kdepim-runtime would default to using unencrypted POP3 communication despite the UI indicating that encryption was in use.

CVE-2020-15954

KDE KMail 19.12.3 (aka 5.13.3) engages in unencrypted POP3 communication during times when the UI indicates that encryption is in use.

For Debian 9 Stretch, these problems have been fixed in version 4:16.04.2-2+deb9u1.

We recommend that you upgrade your kdepim-runtime packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'kdepim-runtime' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);