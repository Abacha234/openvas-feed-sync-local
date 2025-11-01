# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840079");
  script_cve_id("CVE-2007-2423", "CVE-2007-2637");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-458-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-458-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moin' package(s) announced via the USN-458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in MoinMoin's error reporting when using the
AttachFile action. By tricking a user into viewing a crafted MoinMoin
URL, an attacker could execute arbitrary JavaScript as the current
MoinMoin user, possibly exposing the user's authentication information
for the domain where MoinMoin was hosted. (CVE-2007-2423)

Flaws were discovered in MoinMoin's ACL handling for calendars and
includes. Unauthorized users would be able to read pages that would
otherwise be unavailable to them.");

  script_tag(name:"affected", value:"'moin' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
