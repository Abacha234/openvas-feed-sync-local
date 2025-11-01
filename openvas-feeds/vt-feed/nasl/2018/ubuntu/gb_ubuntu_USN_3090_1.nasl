# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843724");
  script_cve_id("CVE-2014-3589", "CVE-2014-9601", "CVE-2016-0740", "CVE-2016-0775", "CVE-2016-2533");
  script_tag(name:"creation_date", value:"2018-10-26 04:11:57 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3090-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3090-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow' package(s) announced via the USN-3090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a flaw in processing a compressed text chunk in
a PNG image could cause the image to have a large size when decompressed,
potentially leading to a denial of service. (CVE-2014-9601)

Andrew Drake discovered that Pillow incorrectly validated input. A remote
attacker could use this to cause Pillow to crash, resulting in a denial
of service. (CVE-2014-3589)

Eric Soroos discovered that Pillow incorrectly handled certain malformed
FLI, Tiff, and PhotoCD files. A remote attacker could use this issue to
cause Pillow to crash, resulting in a denial of service.
(CVE-2016-0740, CVE-2016-0775, CVE-2016-2533)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
