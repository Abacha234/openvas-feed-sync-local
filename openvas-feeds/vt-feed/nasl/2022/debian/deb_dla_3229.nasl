# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893229");
  script_cve_id("CVE-2022-21704");
  script_tag(name:"creation_date", value:"2022-12-07 02:00:53 +0000 (Wed, 07 Dec 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 16:50:00 +0000 (Thu, 27 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-3229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3229");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3229");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-log4js");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-log4js' package(s) announced via the DLA-3229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In node-log4js, a port of log4js in Node.js, default file permissions for log files created by the file, fileSync, and dateFile appenders are world-readable. This could cause problems if log files contain sensitive information. This would affect any users that have not supplied their own permissions for the files via the mode parameter in the config.

For Debian 10 buster, this problem has been fixed in version 4.0.2-2+deb10u1.

We recommend that you upgrade your node-log4js packages.

For the detailed security status of node-log4js please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-log4js' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);