# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703517");
  script_cve_id("CVE-2016-1531");
  script_tag(name:"creation_date", value:"2016-03-13 23:00:00 +0000 (Sun, 13 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");

  script_name("Debian: Security Advisory (DSA-3517)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3517");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3517");
  script_xref(name:"URL", value:"https://www.exim.org/static/doc/CVE-2016-1531.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim4' package(s) announced via the DSA-3517 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A local root privilege escalation vulnerability was found in Exim, Debian's default mail transfer agent, in configurations using the perl_startup option (Only Exim via exim4-daemon-heavy enables Perl support).

To address the vulnerability, updated Exim versions clean the complete execution environment by default, affecting Exim and subprocesses such as transports calling other programs, and thus may break existing installations. New configuration options (keep_environment, add_environment) were introduced to adjust this behavior.

More information can be found in the upstream advisory at [link moved to references]

For the oldstable distribution (wheezy), this problem has been fixed in version 4.80-7+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 4.84.2-1.

For the testing distribution (stretch), this problem has been fixed in version 4.86.2-1.

For the unstable distribution (sid), this problem has been fixed in version 4.86.2-1.

We recommend that you upgrade your exim4 packages.");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);