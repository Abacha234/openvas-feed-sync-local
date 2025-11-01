# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703873");
  script_cve_id("CVE-2017-6512");
  script_tag(name:"creation_date", value:"2017-06-04 22:00:00 +0000 (Sun, 04 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 20:24:00 +0000 (Wed, 29 Apr 2020)");

  script_name("Debian: Security Advisory (DSA-3873)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3873");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3873");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-3873 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The cPanel Security Team reported a time of check to time of use (TOCTTOU) race condition flaw in File::Path, a core module from Perl to create or remove directory trees. An attacker can take advantage of this flaw to set the mode on an attacker-chosen file to a attacker-chosen value.

For the stable distribution (jessie), this problem has been fixed in version 5.20.2-3+deb8u7.

For the upcoming stable distribution (stretch), this problem has been fixed in version 5.24.1-3.

For the unstable distribution (sid), this problem has been fixed in version 5.24.1-3.

We recommend that you upgrade your perl packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);