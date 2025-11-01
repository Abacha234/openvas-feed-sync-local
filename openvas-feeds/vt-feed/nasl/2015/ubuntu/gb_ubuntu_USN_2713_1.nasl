# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842411");
  script_cve_id("CVE-2015-3212", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2015-08-18 04:50:54 +0000 (Tue, 18 Aug 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2713-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2713-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2713-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2713-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marcelo Ricardo Leitner discovered a race condition in the Linux kernel's
SCTP address configuration lists when using Address Configuration Change
(ASCONF) options on a socket. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2015-3212)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker could exploit this flaw to cause a denial of
service using a flood of UDP packets with invalid checksums.
(CVE-2015-5364)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker can cause a denial of service against
applications that use epoll by injecting a single packet with an invalid
checksum. (CVE-2015-5366)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
