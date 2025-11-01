# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703868");
  script_cve_id("CVE-2017-9287");
  script_tag(name:"creation_date", value:"2017-05-29 22:00:00 +0000 (Mon, 29 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-13 19:18:00 +0000 (Mon, 13 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-3868)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3868");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3868");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openldap' package(s) announced via the DSA-3868 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Karsten Heymann discovered that the OpenLDAP directory server can be crashed by performing a paged search with a page size of 0, resulting in denial of service. This vulnerability is limited to the MDB storage backend.

For the stable distribution (jessie), this problem has been fixed in version 2.4.40+dfsg-1+deb8u3.

For the unstable distribution (sid), this problem has been fixed in version 2.4.44+dfsg-5.

We recommend that you upgrade your openldap packages.");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);