# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703643");
  script_cve_id("CVE-2016-6232");
  script_tag(name:"creation_date", value:"2016-08-05 22:00:00 +0000 (Fri, 05 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:31:00 +0000 (Mon, 28 Nov 2016)");

  script_name("Debian: Security Advisory (DSA-3643)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3643");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3643");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kde4libs' package(s) announced via the DSA-3643 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andreas Cord-Landwehr discovered that kde4libs, the core libraries for all KDE 4 applications, do not properly handle the extraction of archives with '../' in the file paths. A remote attacker can take advantage of this flaw to overwrite files outside of the extraction folder, if a user is tricked into extracting a specially crafted archive.

For the stable distribution (jessie), this problem has been fixed in version 4:4.14.2-5+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 4:4.14.22-2.

We recommend that you upgrade your kde4libs packages.");

  script_tag(name:"affected", value:"'kde4libs' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);