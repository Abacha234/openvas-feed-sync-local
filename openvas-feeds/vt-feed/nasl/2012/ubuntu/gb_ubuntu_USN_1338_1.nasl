# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840877");
  script_cve_id("CVE-2011-4623");
  script_tag(name:"creation_date", value:"2012-01-25 05:46:27 +0000 (Wed, 25 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1338-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1338-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog' package(s) announced via the USN-1338-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Eisentraut discovered that Rsyslog would not properly perform input
validation when configured to use imfile. If an attacker were able to
craft messages in a file that Rsyslog monitored, an attacker could cause a
denial of service. The imfile module is disabled by default in Ubuntu.");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
