# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840400");
  script_cve_id("CVE-2010-0668", "CVE-2010-0669", "CVE-2010-0717");
  script_tag(name:"creation_date", value:"2010-03-12 16:02:32 +0000 (Fri, 12 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-911-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-911-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-911-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moin' package(s) announced via the USN-911-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that several wiki actions and preference settings in
MoinMoin were not protected from cross-site request forgery (CSRF). If an
authenticated user were tricked into visiting a malicious website while
logged into MoinMoin, a remote attacker could change the user's
configuration or wiki content. (CVE-2010-0668, CVE-2010-0717)

It was discovered that MoinMoin did not properly sanitize its input when
processing user preferences. An attacker could enter malicious content
which when viewed by a user, could render in unexpected ways.
(CVE-2010-0669)");

  script_tag(name:"affected", value:"'moin' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
