# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891852");
  script_cve_id("CVE-2019-9948");
  script_tag(name:"creation_date", value:"2019-07-12 02:00:07 +0000 (Fri, 12 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 17:14:00 +0000 (Thu, 30 Jun 2022)");

  script_name("Debian: Security Advisory (DLA-1852)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1852");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1852");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python3.4");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python3.4' package(s) announced via the DLA-1852 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The urllib library in Python ships support for a second, not well known URL scheme for accessing local files ('local_file://'). This scheme can be used to circumvent protections that try to block local file access and only block the well-known 'file://' schema. This update addresses the vulnerability by disallowing the 'local_file://' URL scheme.

This update also fixes another regression introduced in the update issued as DLA-1835-1 that broke installation of libpython3.4-testsuite.

For Debian 8 Jessie, this problem has been fixed in version 3.4.2-1+deb8u5.

We recommend that you upgrade your python3.4 packages.

For the detailed security status of python3.4 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python3.4' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);