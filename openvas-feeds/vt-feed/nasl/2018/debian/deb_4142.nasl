# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704142");
  script_cve_id("CVE-2018-7490");
  script_tag(name:"creation_date", value:"2018-03-16 23:00:00 +0000 (Fri, 16 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 15:24:00 +0000 (Fri, 23 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4142");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4142");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/uwsgi");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uwsgi' package(s) announced via the DSA-4142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marios Nicolaides discovered that the PHP plugin in uWSGI, a fast, self-healing application container server, does not properly handle a DOCUMENT_ROOT check during use of the --php-docroot option, allowing a remote attacker to mount a directory traversal attack and gain unauthorized read access to sensitive files located outside of the web root directory.

For the oldstable distribution (jessie), this problem has been fixed in version 2.0.7-1+deb8u2. This update additionally includes the fix for CVE-2018-6758 which was aimed to be addressed in the upcoming jessie point release.

For the stable distribution (stretch), this problem has been fixed in version 2.0.14+20161117-3+deb9u2.

We recommend that you upgrade your uwsgi packages.

For the detailed security status of uwsgi please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'uwsgi' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);