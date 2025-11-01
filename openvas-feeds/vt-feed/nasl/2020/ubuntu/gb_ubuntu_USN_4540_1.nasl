# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844613");
  script_cve_id("CVE-2019-11365", "CVE-2019-11366");
  script_tag(name:"creation_date", value:"2020-09-25 03:00:34 +0000 (Fri, 25 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 18:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4540-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4540-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4540-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'atftp' package(s) announced via the USN-4540-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Denis Andzakovic discovered that atftpd incorrectly handled certain
malformed packets. A remote attacker could send a specially crafted packet
to cause atftpd to crash, resulting in a denial of service.
(CVE-2019-11365)

Denis Andzakovic discovered that atftpd did not properly lock the thread
list mutex. An attacker could send a large number of tftpd packets
simultaneously when running atftpd in daemon mode to cause atftpd to
crash, resulting in a denial of service. (CVE-2019-11366)");

  script_tag(name:"affected", value:"'atftp' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
