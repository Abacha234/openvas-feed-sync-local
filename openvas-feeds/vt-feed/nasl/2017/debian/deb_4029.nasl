# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704029");
  script_cve_id("CVE-2017-8806");
  script_tag(name:"creation_date", value:"2017-11-08 23:00:00 +0000 (Wed, 08 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 18:42:00 +0000 (Fri, 08 Dec 2017)");

  script_name("Debian: Security Advisory (DSA-4029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4029");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4029");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-common' package(s) announced via the DSA-4029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the pg_ctlcluster, pg_createcluster and pg_upgradecluster commands handled symbolic links insecurely which could result in local denial of service by overwriting arbitrary files.

For the oldstable distribution (jessie), this problem has been fixed in version 165+deb8u3.

For the stable distribution (stretch), this problem has been fixed in version 181+deb9u1.

We recommend that you upgrade your postgresql-common packages.");

  script_tag(name:"affected", value:"'postgresql-common' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);