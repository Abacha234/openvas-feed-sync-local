# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840831");
  script_cve_id("CVE-2011-2189");
  script_tag(name:"creation_date", value:"2011-12-09 05:23:10 +0000 (Fri, 09 Dec 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-05 15:12:00 +0000 (Wed, 05 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1288-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1288-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vsftpd' package(s) announced via the USN-1288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the 2.6.35 and earlier Linux kernel does not
properly handle a high rate of creation and cleanup of network namespaces,
which makes it easier for remote attackers to cause a denial of service
(memory consumption) in applications that require a separate namespace per
connection, like vsftpd. This update adjusts vsftpd to only use network
namespaces on kernels that are known to be not affected.");

  script_tag(name:"affected", value:"'vsftpd' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
