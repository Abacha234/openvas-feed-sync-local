# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840172");
  script_cve_id("CVE-2007-3377", "CVE-2007-3409");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-483-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-483-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-483-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnet-dns-perl' package(s) announced via the USN-483-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Johannes Holzer discovered that the Net::DNS Perl module had
predictable sequence numbers. This could allow remote attackers to
carry out DNS spoofing, leading to possible machine-in-the-middle attacks.
(CVE-2007-3377)

Steffen Ullrich discovered that the Net::DNS Perl module did not correctly
detect recursive compressed responses. A remote attacker could send a
specially crafted packet, causing applications using Net::DNS to crash or
monopolize CPU resources, leading to a denial of service. (CVE-2007-3409)");

  script_tag(name:"affected", value:"'libnet-dns-perl' package(s) on Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
